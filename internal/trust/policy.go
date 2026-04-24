package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type PeerAuthorization struct {
	NodeID    string `json:"node_id"`
	PublicKey string `json:"public_key"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type SignedPeerBundle struct {
	NetworkName string              `json:"network_name"`
	GeneratedAt string              `json:"generated_at,omitempty"`
	Entries     []PeerAuthorization `json:"entries"`
	Signature   string              `json:"signature"`
}

type Policy struct {
	networkName string
	required    bool
	authorized  map[string]string
}

func LoadPolicy(networkName, rootPublicKeyFile, signedBundleFile string, directAuthorizedKeys []string, allowUnauthenticated bool) (*Policy, error) {
	policy := &Policy{
		networkName: networkName,
		authorized:  make(map[string]string),
	}

	for _, key := range directAuthorizedKeys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		nodeID, err := NodeIDFromPublicKeyPEM(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid directly authorized public key: %w", err)
		}
		policy.authorized[nodeID] = trimmed
		policy.required = true
	}

	if rootPublicKeyFile == "" && signedBundleFile == "" {
		if allowUnauthenticated {
			return policy, nil
		}
		if len(policy.authorized) > 0 {
			policy.required = true
			return policy, nil
		}
		return nil, fmt.Errorf("no peer authorization source configured: set trust_root_public_key_file and authorized_peers_file, provide authorized_peer_keys, or explicitly set allow_unauthenticated_peers for lab use")
	}
	if allowUnauthenticated {
		return nil, fmt.Errorf("allow_unauthenticated_peers cannot be enabled together with an authorization policy")
	}
	if rootPublicKeyFile == "" || signedBundleFile == "" {
		return nil, fmt.Errorf("both trust_root_public_key_file and authorized_peers_file must be set")
	}

	rootPublicKey, err := loadRootPublicKey(rootPublicKeyFile)
	if err != nil {
		return nil, err
	}

	bundle, err := loadSignedBundle(signedBundleFile)
	if err != nil {
		return nil, err
	}

	if bundle.NetworkName != networkName {
		return nil, fmt.Errorf("signed bundle network mismatch: expected %s, got %s", networkName, bundle.NetworkName)
	}

	if err := verifyBundle(rootPublicKey, bundle); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	for _, entry := range bundle.Entries {
		if entry.NodeID == "" || entry.PublicKey == "" {
			return nil, fmt.Errorf("signed bundle contains incomplete entry")
		}

		derivedNodeID, err := NodeIDFromPublicKeyPEM(entry.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid authorized peer key for %s: %w", entry.NodeID, err)
		}
		if derivedNodeID != entry.NodeID {
			return nil, fmt.Errorf("authorized peer %s does not match its public key", entry.NodeID)
		}

		if entry.ExpiresAt != "" {
			expiresAt, err := time.Parse(time.RFC3339, entry.ExpiresAt)
			if err != nil {
				return nil, fmt.Errorf("invalid expiry for authorized peer %s: %w", entry.NodeID, err)
			}
			if now.After(expiresAt) {
				continue
			}
		}

		policy.authorized[entry.NodeID] = entry.PublicKey
	}

	policy.required = true
	return policy, nil
}

func (p *Policy) Required() bool {
	return p != nil && p.required
}

func (p *Policy) IsAuthorized(nodeID, publicKey string) bool {
	if p == nil || !p.required {
		return true
	}

	authorizedKey, ok := p.authorized[nodeID]
	if !ok {
		return false
	}

	return authorizedKey == publicKey
}

func (p *Policy) AuthorizedNodeIDs() []string {
	if p == nil {
		return nil
	}
	nodeIDs := make([]string, 0, len(p.authorized))
	for nodeID := range p.authorized {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Strings(nodeIDs)
	return nodeIDs
}

func NodeIDFromPublicKeyPEM(publicKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}

	edPublicKey, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("public key is not Ed25519")
	}

	return NodeIDFromEd25519PublicKey(edPublicKey), nil
}

func NodeIDFromEd25519PublicKey(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return fmt.Sprintf("%x", sum[:16])
}

func loadRootPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read trust root public key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid trust root public key PEM")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trust root public key: %w", err)
	}

	edPublicKey, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("trust root public key is not Ed25519")
	}

	return edPublicKey, nil
}

func loadSignedBundle(path string) (*SignedPeerBundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read authorized peers bundle: %w", err)
	}

	var bundle SignedPeerBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("failed to parse authorized peers bundle: %w", err)
	}
	return &bundle, nil
}

func verifyBundle(rootPublicKey ed25519.PublicKey, bundle *SignedPeerBundle) error {
	signature, err := base64.StdEncoding.DecodeString(bundle.Signature)
	if err != nil {
		return fmt.Errorf("invalid authorized peers bundle signature encoding: %w", err)
	}

	payload := bundleSigningPayload(bundle.NetworkName, bundle.GeneratedAt, bundle.Entries)
	if !ed25519.Verify(rootPublicKey, payload, signature) {
		return fmt.Errorf("authorized peers bundle signature verification failed")
	}

	return nil
}

func bundleSigningPayload(networkName, generatedAt string, entries []PeerAuthorization) []byte {
	copied := make([]PeerAuthorization, 0, len(entries))
	for _, entry := range entries {
		copied = append(copied, entry)
	}

	sort.Slice(copied, func(i, j int) bool {
		if copied[i].NodeID == copied[j].NodeID {
			return copied[i].PublicKey < copied[j].PublicKey
		}
		return copied[i].NodeID < copied[j].NodeID
	})

	type payloadEntry struct {
		NodeID    string `json:"node_id"`
		PublicKey string `json:"public_key"`
		ExpiresAt string `json:"expires_at,omitempty"`
	}

	payload := struct {
		NetworkName string         `json:"network_name"`
		GeneratedAt string         `json:"generated_at,omitempty"`
		Entries     []payloadEntry `json:"entries"`
	}{
		NetworkName: networkName,
		GeneratedAt: generatedAt,
		Entries:     make([]payloadEntry, 0, len(copied)),
	}

	for _, entry := range copied {
		payload.Entries = append(payload.Entries, payloadEntry{
			NodeID:    entry.NodeID,
			PublicKey: entry.PublicKey,
			ExpiresAt: entry.ExpiresAt,
		})
	}

	data, _ := json.Marshal(payload)
	return data
}

// SignBundle is a helper for tests and tooling that prepares a signed authorization bundle.
func SignBundle(networkName string, rootPrivateKey ed25519.PrivateKey, entries []PeerAuthorization) (*SignedPeerBundle, error) {
	bundle := &SignedPeerBundle{
		NetworkName: networkName,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Entries:     entries,
	}
	payload := bundleSigningPayload(bundle.NetworkName, bundle.GeneratedAt, bundle.Entries)
	bundle.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(rootPrivateKey, payload))
	return bundle, nil
}

func GenerateRootKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
