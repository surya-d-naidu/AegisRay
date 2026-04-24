package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/surya-d-naidu/AegisRay/internal/crypto"
	"github.com/surya-d-naidu/AegisRay/internal/trust"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "gen-root":
		err = runGenRoot(os.Args[2:])
	case "show-node":
		err = runShowNode(os.Args[2:])
	case "sign-bundle":
		err = runSignBundle(os.Args[2:])
	case "verify-bundle":
		err = runVerifyBundle(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `AegisRay trust tooling

Usage:
  aegisray-trust <command> [flags]

Commands:
  gen-root      Generate an Ed25519 trust root keypair
  show-node     Print a node's public key and derived node ID
  sign-bundle   Build and sign an authorized peers bundle
  verify-bundle Verify a signed authorized peers bundle

Examples:
  aegisray-trust gen-root -out-private trust-root.key -out-public trust-root.pem
  aegisray-trust show-node -identity-key certs/identity.key
  aegisray-trust sign-bundle -network corp-net -root-key trust-root.key -peer-key-file peer1.pem -peer-key-file peer2.pem -out authorized-peers.json
  aegisray-trust verify-bundle -network corp-net -root-public-key trust-root.pem -bundle authorized-peers.json
`)
}

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func runGenRoot(args []string) error {
	fs := flag.NewFlagSet("gen-root", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	outPrivate := fs.String("out-private", "trust-root.key", "path to write the PKCS8 private key PEM")
	outPublic := fs.String("out-public", "trust-root.pem", "path to write the public key PEM")

	if err := fs.Parse(args); err != nil {
		return err
	}

	publicKey, privateKey, err := trust.GenerateRootKeyPair()
	if err != nil {
		return err
	}

	if err := writePrivateKey(*outPrivate, privateKey); err != nil {
		return err
	}

	publicKeyPEM, err := crypto.PublicKeyPEM(publicKey)
	if err != nil {
		return err
	}
	if err := writeFileWithMkdir(*outPublic, publicKeyPEM, 0644); err != nil {
		return err
	}

	fmt.Printf("wrote %s and %s\n", *outPrivate, *outPublic)
	return nil
}

func runShowNode(args []string) error {
	fs := flag.NewFlagSet("show-node", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	identityKeyPath := fs.String("identity-key", "", "path to node Ed25519 PKCS8 private key PEM")
	publicKeyPath := fs.String("public-key", "", "path to node public key PEM")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*identityKeyPath == "" && *publicKeyPath == "") || (*identityKeyPath != "" && *publicKeyPath != "") {
		return errors.New("provide exactly one of -identity-key or -public-key")
	}

	var publicKeyPEM []byte
	var err error
	if *identityKeyPath != "" {
		privateKey, err := crypto.LoadIdentityKey(*identityKeyPath)
		if err != nil {
			return err
		}
		publicKeyPEM, err = crypto.PublicKeyPEM(privateKey.Public())
		if err != nil {
			return err
		}
	} else {
		publicKeyPEM, err = os.ReadFile(*publicKeyPath)
		if err != nil {
			return err
		}
	}

	nodeID, err := trust.NodeIDFromPublicKeyPEM(string(publicKeyPEM))
	if err != nil {
		return err
	}

	output := map[string]string{
		"node_id":    nodeID,
		"public_key": string(publicKeyPEM),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func runSignBundle(args []string) error {
	fs := flag.NewFlagSet("sign-bundle", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	networkName := fs.String("network", "", "mesh network name")
	rootKeyPath := fs.String("root-key", "", "path to Ed25519 trust root private key PEM")
	outPath := fs.String("out", "authorized-peers.json", "output bundle path")
	expiresAt := fs.String("expires-at", "", "optional RFC3339 expiry applied to every listed peer")
	var peerKeyFiles multiFlag
	fs.Var(&peerKeyFiles, "peer-key-file", "path to an authorized peer public key PEM; repeatable")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *networkName == "" || *rootKeyPath == "" {
		return errors.New("-network and -root-key are required")
	}
	if len(peerKeyFiles) == 0 {
		return errors.New("at least one -peer-key-file is required")
	}

	rootPrivateKey, err := loadRootPrivateKey(*rootKeyPath)
	if err != nil {
		return err
	}

	entries := make([]trust.PeerAuthorization, 0, len(peerKeyFiles))
	for _, keyPath := range peerKeyFiles {
		publicKeyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("read peer key %s: %w", keyPath, err)
		}
		nodeID, err := trust.NodeIDFromPublicKeyPEM(string(publicKeyPEM))
		if err != nil {
			return fmt.Errorf("parse peer key %s: %w", keyPath, err)
		}

		entries = append(entries, trust.PeerAuthorization{
			NodeID:    nodeID,
			PublicKey: string(publicKeyPEM),
			ExpiresAt: *expiresAt,
		})
	}

	bundle, err := trust.SignBundle(*networkName, rootPrivateKey, entries)
	if err != nil {
		return err
	}

	bundleBytes, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileWithMkdir(*outPath, bundleBytes, 0644); err != nil {
		return err
	}

	fmt.Printf("wrote %s with %d authorized peer(s)\n", *outPath, len(entries))
	return nil
}

func runVerifyBundle(args []string) error {
	fs := flag.NewFlagSet("verify-bundle", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	networkName := fs.String("network", "", "mesh network name")
	rootPublicKeyPath := fs.String("root-public-key", "", "path to trust root public key PEM")
	bundlePath := fs.String("bundle", "", "path to signed bundle JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *networkName == "" || *rootPublicKeyPath == "" || *bundlePath == "" {
		return errors.New("-network, -root-public-key, and -bundle are required")
	}

	policy, err := trust.LoadPolicy(*networkName, *rootPublicKeyPath, *bundlePath, nil, false)
	if err != nil {
		return err
	}

	fmt.Printf("bundle verified for network %s with %d authorized peer(s)\n", *networkName, len(policy.AuthorizedNodeIDs()))
	return nil
}

func writePrivateKey(path string, privateKey ed25519.PrivateKey) error {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	return writeFileWithMkdir(path, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}), 0600)
}

func loadRootPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid trust root private key PEM")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	edPrivateKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("trust root private key is not Ed25519")
	}
	return edPrivateKey, nil
}

func writeFileWithMkdir(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, data, mode)
}
