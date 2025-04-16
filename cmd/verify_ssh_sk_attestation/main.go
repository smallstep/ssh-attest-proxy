package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

type ssh_sk_attestation struct {
	Type          string
	Certificate   []byte
	Signature     []byte
	AuthData      []byte
	ReservedFlags uint32
	Reserved      []byte
}

func verifyAttestationSignature(att ssh_sk_attestation, challenge []byte) error {
	// """Verify the attestation signature.

	// Args:
	// 	attestation: Parsed attestation data
	// 	challenge: Challenge bytes used during key generation
	// """

	authData := att.AuthData
	clientDataHash := sha256.Sum256(challenge)
	signedData := append(authData, clientDataHash[:]...)

	// Parse the DER-encoded attestation certificate
	attestationCert, err := x509.ParseCertificate(att.Certificate)
	if err != nil {
		return fmt.Errorf("failed to parse attestation certificate: %v", err)
	}

	// Verify the attestation signature
	pubKey, ok := attestationCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("attestation certificate public key is not an ECDSA key")
	}

	if !ecdsa.VerifyASN1(pubKey, signedData, att.Signature) {
		return fmt.Errorf("attestation signature verification failed")
	}

	return nil
}

func verifyAttestation(att ssh_sk_attestation, challenge []byte, pubkey ssh.PublicKey) error {
	if err := verifyAttestationSignature(att, challenge); err != nil {
		return fmt.Errorf("failed to verify attestation signature: %v", err)
	}

	// Parse the attestation data
	// Verify that the pubkey matches the credential data

	return nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <username> <certificate>\n", os.Args[0])
		os.Exit(1)
	}

	username := os.Args[1]
	certBase64 := os.Args[2]

	// Decode the base64 certificate
	certBytes, err := base64.StdEncoding.DecodeString(certBase64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding certificate: %v\n", err)
		os.Exit(1)
	}

	// Parse the certificate
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing certificate: %v\n", err)
		os.Exit(1)
	}

	cert, ok := pubkey.(*ssh.Certificate)
	if !ok {
		fmt.Fprintf(os.Stderr, "Not a certificate\n")
		os.Exit(1)
	}

	// Check for the custom extension
	extValue, ok := cert.Permissions.Extensions["ssh-sk-attest-v01@openssh.com"]
	if !ok {
		fmt.Fprintf(os.Stderr, "Custom extension not found\n")
		os.Exit(1)
	}

	// Decode the extension value
	extBytes, err := base64.StdEncoding.DecodeString(extValue)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding extension: %v\n", err)
		os.Exit(1)
	}

	// Parse the extension data
	// Format: string "ssh-sk-attest-v01", attestation data, challenge
	// Each field is preceded by a 4-byte length in big-endian
	if len(extBytes) < 4 {
		fmt.Fprintf(os.Stderr, "Invalid extension data\n")
		os.Exit(1)
	}
	versionLen := binary.BigEndian.Uint32(extBytes[:4])
	if len(extBytes) < int(4+versionLen) {
		fmt.Fprintf(os.Stderr, "Invalid extension data\n")
		os.Exit(1)
	}
	version := string(extBytes[4 : 4+versionLen])
	if version != "ssh-sk-attest-v01" {
		fmt.Fprintf(os.Stderr, "Unexpected version: %s\n", version)
		os.Exit(1)
	}
	extBytes = extBytes[4+versionLen:]

	if len(extBytes) < 4 {
		fmt.Fprintf(os.Stderr, "Invalid extension data\n")
		os.Exit(1)
	}
	attestationLen := binary.BigEndian.Uint32(extBytes[:4])
	if len(extBytes) < int(4+attestationLen) {
		fmt.Fprintf(os.Stderr, "Invalid extension data\n")
		os.Exit(1)
	}
	attestationData := extBytes[4 : 4+attestationLen]
	extBytes = extBytes[4+attestationLen:]

	var att ssh_sk_attestation
	if err := ssh.Unmarshal(attestationData, &att); err != nil {
		fmt.Fprintf(os.Stderr, "failed to unmarshal attestation: %v", err)
		os.Exit(1)
	}

	if len(extBytes) < 4 {
		fmt.Fprintf(os.Stderr, "Invalid extension data\n")
		os.Exit(1)
	}
	challengeLen := binary.BigEndian.Uint32(extBytes[:4])
	if len(extBytes) < int(4+challengeLen) {
		fmt.Fprintf(os.Stderr, "Invalid extension data\n")
		os.Exit(1)
	}
	challenge := extBytes[4 : 4+challengeLen]

	// Verify the attestation
	if err := verifyAttestation(att, challenge, pubkey); err != nil {
		fmt.Fprintf(os.Stderr, "Error verifying attestation: %v\n", err)
		os.Exit(1)
	}

	// Check if the username is in the list of principals, or if the list is empty
	if len(cert.ValidPrincipals) == 0 {
		fmt.Println(username)
		os.Exit(0)
	}

	for _, p := range cert.ValidPrincipals {
		if p == username {
			fmt.Println(username)
			os.Exit(0)
		}
	}

	fmt.Fprintf(os.Stderr, "Username not in certificate principals\n")
	os.Exit(1)
}
