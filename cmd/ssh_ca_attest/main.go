package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

func parseSSHPrivateKey(keyPath string) (interface{}, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %v", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		// If it's an Ed25519 key, ensure it's the correct type
		if k, ok := key.(ed25519.PrivateKey); ok {
			return k, nil
		}
		return key, nil
	case "OPENSSH PRIVATE KEY":
		key, err := ssh.ParseRawPrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse OpenSSH private key: %v", err)
		}
		// If it's an Ed25519 key pointer, dereference
		if k, ok := key.(*ed25519.PrivateKey); ok {
			return *k, nil
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

func parseSSHPublicKey(pubkeyPath string) (ssh.PublicKey, error) {
	pubkeyBytes, err := os.ReadFile(pubkeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %v", err)
	}

	pubkey, _, _, _, err := ssh.ParseAuthorizedKey(pubkeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	return pubkey, nil
}

func createCustomExtension(attestationData, challenge []byte) []byte {
	// Format: string "ssh-sk-attest-v01", attestation data, challenge
	extension := make([]byte, 0)

	// Add version string
	version := []byte("ssh-sk-attest-v01")
	versionLen := make([]byte, 4)
	binary.BigEndian.PutUint32(versionLen, uint32(len(version)))
	extension = append(extension, versionLen...)
	extension = append(extension, version...)

	// Add attestation data
	attestationLen := make([]byte, 4)
	binary.BigEndian.PutUint32(attestationLen, uint32(len(attestationData)))
	extension = append(extension, attestationLen...)
	extension = append(extension, attestationData...)

	// Add challenge
	challengeLen := make([]byte, 4)
	binary.BigEndian.PutUint32(challengeLen, uint32(len(challenge)))
	extension = append(extension, challengeLen...)
	extension = append(extension, challenge...)

	return extension
}

func signSSHCertificate(caKey interface{}, cert *ssh.Certificate, attestationData, challenge []byte) error {
	// Add custom extension
	customExt := createCustomExtension(attestationData, challenge)
	cert.Permissions.Extensions["ssh-sk-attest-v01@openssh.com"] = base64.StdEncoding.EncodeToString(customExt)

	// Sign the certificate
	switch key := caKey.(type) {
	case *rsa.PrivateKey:
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			return fmt.Errorf("failed to create signer: %v", err)
		}
		return cert.SignCert(rand.Reader, signer)
	case ed25519.PrivateKey:
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			return fmt.Errorf("failed to create signer: %v", err)
		}
		return cert.SignCert(rand.Reader, signer)
	case *ed25519.PrivateKey:
		signer, err := ssh.NewSignerFromKey(*key)
		if err != nil {
			return fmt.Errorf("failed to create signer: %v", err)
		}
		return cert.SignCert(rand.Reader, signer)
	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}
}

func main() {
	if len(os.Args) != 7 {
		fmt.Fprintf(os.Stderr, "Usage: %s <ca-key> <pubkey> <attestation> <challenge> <principals> <output>\n", os.Args[0])
		os.Exit(1)
	}

	caKeyPath := os.Args[1]
	pubkeyPath := os.Args[2]
	attestationPath := os.Args[3]
	challengePath := os.Args[4]
	principalsArg := os.Args[5]
	outputPath := os.Args[6]

	// Parse CA private key
	caKey, err := parseSSHPrivateKey(caKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing CA key: %v\n", err)
		os.Exit(1)
	}

	// Parse public key
	pubkey, err := parseSSHPublicKey(pubkeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing public key: %v\n", err)
		os.Exit(1)
	}

	// Parse principals
	var principals []string
	if principalsArg != "" {
		for _, p := range splitAndTrim(principalsArg, ",") {
			if p != "" {
				principals = append(principals, p)
			}
		}
	}

	// Create certificate
	cert := &ssh.Certificate{
		Key:             pubkey,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "key-attestation",
		ValidPrincipals: principals,
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Add(365 * 24 * time.Hour).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      map[string]string{},
		},
	}

	// Read attestation data
	attestationData, err := os.ReadFile(attestationPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading attestation data: %v\n", err)
		os.Exit(1)
	}

	// Read challenge
	challenge, err := os.ReadFile(challengePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading challenge: %v\n", err)
		os.Exit(1)
	}

	// Sign the certificate
	if err := signSSHCertificate(caKey, cert, attestationData, challenge); err != nil {
		fmt.Fprintf(os.Stderr, "Error signing certificate: %v\n", err)
		os.Exit(1)
	}

	// Write the certificate
	certBytes := ssh.MarshalAuthorizedKey(cert)
	if err := os.WriteFile(outputPath, certBytes, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing certificate: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Certificate successfully signed and written to %s\n", outputPath)
}

func splitAndTrim(s, sep string) []string {
	var out []string
	for _, part := range splitNoEmpty(s, sep) {
		out = append(out, trimSpace(part))
	}
	return out
}

func splitNoEmpty(s, sep string) []string {
	var out []string
	for _, part := range split(s, sep) {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func split(s, sep string) []string {
	return []string{os.ExpandEnv(s)} // fallback, will be replaced below
}

func trimSpace(s string) string {
	return s // fallback, will be replaced below
}
