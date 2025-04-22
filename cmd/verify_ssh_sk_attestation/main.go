package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"os"

	"github.com/coreos/go-systemd/v22/journal"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"golang.org/x/crypto/ssh"
)

type sshSKAttestation struct {
	Type          string
	Certificate   []byte
	Signature     []byte
	AuthData      []byte
	ReservedFlags uint32
	Reserved      []byte
}

func verifyAttestationSignature(att sshSKAttestation, challenge []byte) error {
	// """Verify the attestation signature.

	// Args:
	// 	attestation: Parsed attestation data
	// 	challenge: Challenge bytes used during key generation
	// """

	clientDataHash := sha256.Sum256(challenge)
	signedData := make([]byte, len(att.AuthData)+len(clientDataHash))
	copy(signedData, att.AuthData)
	copy(signedData[len(att.AuthData):], clientDataHash[:])

	// Parse the DER-encoded attestation certificate
	attestationCert, err := x509.ParseCertificate(att.Certificate)
	if err != nil {
		return fmt.Errorf("failed to parse attestation certificate: %w", err)
	}

	// Verify the attestation signature
	pubKey, ok := attestationCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("attestation certificate public key is not an ECDSA key")
	}
	if pubKey.Curve != elliptic.P256() {
		return fmt.Errorf("attestation certificate public key ECDSA curve is not supported")
	}

	sum := sha256.Sum256(signedData)
	if !ecdsa.VerifyASN1(pubKey, sum[:], att.Signature) {
		return fmt.Errorf("attestation signature verification failed")
	}

	return nil
}

func verifyAttestation(att sshSKAttestation, challenge []byte, pubkey ssh.PublicKey) error {
	if err := verifyAttestationSignature(att, challenge); err != nil {
		return fmt.Errorf("failed to verify attestation signature: %w", err)
	}

	if cert, ok := pubkey.(*ssh.Certificate); ok {
		pubkey = cert.Key
	}

	cpk, ok := pubkey.(ssh.CryptoPublicKey)
	if !ok {
		return fmt.Errorf("ssh public key does not implement ssh.CryptoPublicKey")
	}

	// Parse the authenticator data
	var authData protocol.AuthenticatorData
	if err := authData.Unmarshal(att.AuthData); err != nil {
		return fmt.Errorf("failed to unmarshal authenticator data: %w", err)
	}

	// Verify that the pubkey matches the credential data
	credPubKey, err := webauthncose.ParsePublicKey(authData.AttData.CredentialPublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse credential public key: %w", err)
	}

	switch k := credPubKey.(type) {
	case webauthncose.EC2PublicKeyData:
		ecdsaKey, ok := cpk.CryptoPublicKey().(*ecdsa.PublicKey)
		if !ok || !bytes.Equal(k.XCoord, ecdsaKey.X.Bytes()) || !bytes.Equal(k.YCoord, ecdsaKey.Y.Bytes()) {
			return fmt.Errorf("public key does not match the public key in the attestation")
		}
	case webauthncose.OKPPublicKeyData:
		edKey, ok := cpk.CryptoPublicKey().(ed25519.PublicKey)
		if !ok || !bytes.Equal(k.XCoord, []byte(edKey)) {
			return fmt.Errorf("public key does not match the public key in the attestation")
		}
	default:
		return fmt.Errorf("unsupported credential public key of type %T", k)
	}

	return nil
}

func logError(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	journal.Send(msg, journal.PriErr, map[string]string{
		"SYSLOG_IDENTIFIER": "verify-ssh-sk",
	})
	fmt.Fprintf(os.Stderr, format + "\n", args)
}

func log(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	journal.Send(msg, journal.PriInfo, map[string]string{
		"SYSLOG_IDENTIFIER": "verify-ssh-sk",
	})
}

func usage() {
	w := flag.CommandLine.Output()
	fmt.Fprintf(w, "Usage: %s [--ca ca.pem] <username> <key type> <certificate>\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(1)
}

func main() {
	var caFile string
	flag.StringVar(&caFile, "ca", "", "Root certificates used to verify the attestation certificate.")
	flag.Usage = usage
	flag.Parse()

	if len(flag.Args()) != 3 {
		flag.Usage()
		logError("Wrong number of program arguments")
		os.Exit(1)
	}

	username := flag.Arg(0)
	keyType := flag.Arg(1)
	certBase64 := flag.Arg(2)
	certLine := keyType + " " + certBase64

	// Parse the certificate
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certLine))
	if err != nil {
		logError("Error decoding certificate: %v", err)
		os.Exit(1)
	}

	cert, ok := pubkey.(*ssh.Certificate)
	if !ok {
		logError("Not a certificate")
		os.Exit(1)
	}

	// Check for the custom extension
	extValue, ok := cert.Permissions.Extensions["ssh-sk-attest-v01@step.sm"]
	if !ok {
		logError("Custom extension 'ssk-sk-attest-v01@step.sm` not found")
		os.Exit(1)
	}

	// Decode the extension value
	extBytes, err := base64.StdEncoding.DecodeString(extValue)
	if err != nil {
		logError("Error decoding extension: %v", err)
		os.Exit(1)
	}

	// Parse the extension data
	// Format: string "ssh-sk-attest-v01", attestation data, challenge
	// Each field is preceded by a 4-byte length in big-endian
	if len(extBytes) < 4 {
		logError("Error decoding extension: %v", err)
		os.Exit(1)
	}
	versionLen := binary.BigEndian.Uint32(extBytes[:4])
	if len(extBytes) < int(4+versionLen) {
		logError("Invalid extension data")
		os.Exit(1)
	}
	version := string(extBytes[4 : 4+versionLen])
	if version != "ssh-sk-attest-v01" {
		logError("Unexpected version: %s\n", version)
		os.Exit(1)
	}
	extBytes = extBytes[4+versionLen:]

	if len(extBytes) < 4 {
		logError("Invalid attestation data")
		os.Exit(1)
	}
	attestationLen := binary.BigEndian.Uint32(extBytes[:4])
	if len(extBytes) < int(4+attestationLen) {
		logError("Invalid extension data")
		os.Exit(1)
	}
	attestationData := extBytes[4 : 4+attestationLen]
	extBytes = extBytes[4+attestationLen:]

	var att sshSKAttestation
	if err := ssh.Unmarshal(attestationData, &att); err != nil {
		logError("Failed to unmarshal attestation: %v", err)
		os.Exit(1)
	}

	if caFile != "" {
		attestationCert, err := x509.ParseCertificate(att.Certificate)
		if err != nil {
			logError("Failed to parse attestation certificate: %v", err)
			os.Exit(1)
		}

		b, err := os.ReadFile(caFile)
		if err != nil {
			logError("Failed to open ca file: %v", err)
			os.Exit(1)
		}

		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(b)

		if _, err := attestationCert.Verify(x509.VerifyOptions{
			Roots:     pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			logError("Failed to verify attestation certificate: %v", err)
			os.Exit(1)
		}
	}

	// Authenticator data is CBOR encoded
	var authData []byte
	if err := cbor.Unmarshal(att.AuthData, &authData); err != nil {
		logError("Failed to unmarshal authenticator data: %v", err)
		os.Exit(1)
	}
	att.AuthData = authData

	if len(extBytes) < 4 {
		logError("Invalid extension data")
		os.Exit(1)
	}
	challengeLen := binary.BigEndian.Uint32(extBytes[:4])
	if len(extBytes) < int(4+challengeLen) {
		logError("Invalid challenge length")
		os.Exit(1)
	}
	challenge := extBytes[4 : 4+challengeLen]

	// Verify the attestation
	if err := verifyAttestation(att, challenge, pubkey); err != nil {
		logError("Error verifying attestation: %v", err)
		os.Exit(1)
	}

	// Check if the username is in the list of principals, or if the list is empty
	if len(cert.ValidPrincipals) == 0 {
		log("Successfully verified attestation for %s", username)
		fmt.Println(username)
		os.Exit(0)
	}

	for _, p := range cert.ValidPrincipals {
		if p == username {
			log("Successfully verified attestation for %s", username)
			fmt.Println(username)
			os.Exit(0)
		}
	}

	logError("Username not in certificate principals")
	os.Exit(1)
}
