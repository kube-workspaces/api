// Package updates verifies publisher-authenticated agent-update manifests,
// authenticated machine inventory reports and the write-ahead upgrade journal,
// plus bounded payload streams. It grants no permission to install, downloads
// nothing and does not implement the updater, management transport or job
// lifecycle.
package updates

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	Domain                  = "kw-agent-update-manifest/v1\x00"
	MaxManifestBytes        = 64 * 1024
	MaxArtifactBytes uint64 = 2 * 1024 * 1024 * 1024
	AgentUpgradeCode        = "f72bb43e-dba8-4dbb-a963-b201e6c0d885"
)

var (
	ErrInvalid   = errors.New("invalid agent update manifest")
	ErrUntrusted = errors.New("agent update publisher is not trusted")
	ErrDigest    = errors.New("agent update manifest digest mismatch")
	ErrSignature = errors.New("agent update manifest signature mismatch")
	ErrPayload   = errors.New("agent update payload is incomplete, oversized or corrupt")
	identifier   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	guid         = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hardwareID   = regexp.MustCompile(`^[A-Za-z0-9_.&\\-]{1,128}$`)
)

type Artifact struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   uint64 `json:"size"`
}

type MSI struct {
	Artifact    Artifact `json:"artifact"`
	ProductCode string   `json:"product_code"`
	UpgradeCode string   `json:"upgrade_code"`
}

type Updater struct {
	Artifact        Artifact `json:"artifact"`
	ProtocolVersion uint16   `json:"protocol_version"`
}

type Driver struct {
	Artifact     Artifact `json:"artifact"`
	Version      string   `json:"version"`
	SignerSHA256 string   `json:"signer_sha256"`
	HardwareIDs  []string `json:"hardware_ids"`
}

type Compatibility struct {
	MinimumAgentVersion string `json:"minimum_agent_version"`
	MaximumAgentVersion string `json:"maximum_agent_version"`
	ManagementMin       uint16 `json:"management_min"`
	ManagementMax       uint16 `json:"management_max"`
	DesktopMin          uint16 `json:"desktop_min"`
	DesktopMax          uint16 `json:"desktop_max"`
}

type Predecessor struct {
	TargetID       string `json:"target_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

type Manifest struct {
	Version              uint32        `json:"version"`
	TargetID             string        `json:"target_id"`
	OS                   string        `json:"os"`
	Architecture         string        `json:"architecture"`
	AgentVersion         string        `json:"agent_version"`
	BuildSHA256          string        `json:"build_sha256"`
	MSI                  MSI           `json:"msi"`
	Updater              Updater       `json:"updater"`
	Driver               *Driver       `json:"driver,omitempty"`
	Compatibility        Compatibility `json:"compatibility"`
	RollbackPredecessors []Predecessor `json:"rollback_predecessors"`
	RebootPolicy         string        `json:"reboot_policy"`
}

// VerifiedManifest keeps its verified payload identities private. Metadata()
// returns a deep copy so display/availability callers cannot replace the hashes
// used by VerifyArtifact after publisher verification.
type VerifiedManifest struct {
	manifest Manifest
	digest   string
}

func KeyID(key ed25519.PublicKey) string {
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:16])
}

func Digest(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// Verify requires an operator-pinned manifest digest and independently supplied
// publisher keyring. No trust key or download URL comes from the signed body.
// Signatures cover the domain plus the exact raw bytes, including whitespace.
func Verify(raw, signature []byte, keyID, expectedDigest string, keys map[string]ed25519.PublicKey) (*VerifiedManifest, error) {
	if len(raw) == 0 || len(raw) > MaxManifestBytes || !utf8.Valid(raw) {
		return nil, ErrInvalid
	}
	if len(keys) == 0 || len(keys) > 16 {
		return nil, ErrUntrusted
	}
	for id, public := range keys {
		if len(public) != ed25519.PublicKeySize || id != KeyID(public) {
			return nil, ErrUntrusted
		}
	}
	public, ok := keys[keyID]
	if !ok {
		return nil, ErrUntrusted
	}
	if !validDigest(expectedDigest) || Digest(raw) != expectedDigest {
		return nil, ErrDigest
	}
	if !ed25519.Verify(public, append([]byte(Domain), raw...), signature) {
		return nil, ErrSignature
	}
	if err := uniqueJSON(raw); err != nil {
		return nil, ErrInvalid
	}
	if err := exactFields(raw, reflect.TypeOf(Manifest{})); err != nil {
		return nil, ErrInvalid
	}
	var m Manifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&m) != nil || decoder.Decode(new(interface{})) != io.EOF || !m.valid() {
		return nil, ErrInvalid
	}
	return &VerifiedManifest{manifest: m, digest: expectedDigest}, nil
}

func (v *VerifiedManifest) SHA256() string { return v.digest }

func (v *VerifiedManifest) Metadata() Manifest {
	m := v.manifest
	m.RollbackPredecessors = append([]Predecessor{}, m.RollbackPredecessors...)
	if m.Driver != nil {
		d := *m.Driver
		d.HardwareIDs = append([]string{}, d.HardwareIDs...)
		m.Driver = &d
	}
	return m
}

// VerifyArtifact reads at most the signed size plus one byte. It never buffers
// an entire installer, accepts trailing content, or trusts a caller's size/hash.
func (v *VerifiedManifest) VerifyArtifact(name string, reader io.Reader) error {
	if reader == nil {
		return ErrPayload
	}
	artifacts := []Artifact{v.manifest.MSI.Artifact, v.manifest.Updater.Artifact}
	if v.manifest.Driver != nil {
		artifacts = append(artifacts, v.manifest.Driver.Artifact)
	}
	for _, a := range artifacts {
		if a.File != name {
			continue
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(reader, int64(a.Size)+1))
		if err != nil || uint64(n) != a.Size || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
			return ErrPayload
		}
		return nil
	}
	return ErrPayload
}

func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

func (a Artifact) valid(extension string) bool {
	if !identifier.MatchString(a.File) || strings.HasSuffix(a.File, ".") || !strings.HasSuffix(a.File, extension) || a.Size == 0 || a.Size > MaxArtifactBytes || !validDigest(a.SHA256) {
		return false
	}
	stem := strings.SplitN(a.File, ".", 2)[0]
	if stem == "con" || stem == "prn" || stem == "aux" || stem == "nul" {
		return false
	}
	return len(stem) != 4 || (!strings.HasPrefix(stem, "com") && !strings.HasPrefix(stem, "lpt")) || stem[3] < '1' || stem[3] > '9'
}

func version(s string, parts int) ([]uint64, bool) {
	components := strings.Split(s, ".")
	if len(components) != parts {
		return nil, false
	}
	v := make([]uint64, parts)
	for i, c := range components {
		n, err := strconv.ParseUint(c, 10, 16)
		if err != nil || strconv.FormatUint(n, 10) != c || (parts == 3 && i < 2 && n > 255) {
			return nil, false
		}
		v[i] = n
	}
	return v, true
}

func orderedVersions(a, b string) bool {
	x, ok := version(a, 3)
	if !ok {
		return false
	}
	y, ok := version(b, 3)
	if !ok {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return true
}

func (m Manifest) valid() bool {
	_, versionOK := version(m.AgentVersion, 3)
	c := m.Compatibility
	if m.Version != 1 || !identifier.MatchString(m.TargetID) || m.OS != "windows" || m.Architecture != "amd64" || !versionOK || !validDigest(m.BuildSHA256) {
		return false
	}
	if !m.MSI.Artifact.valid(".msi") || !guid.MatchString(m.MSI.ProductCode) || m.MSI.ProductCode == "00000000-0000-0000-0000-000000000000" || m.MSI.UpgradeCode != AgentUpgradeCode || m.MSI.ProductCode == m.MSI.UpgradeCode {
		return false
	}
	if !m.Updater.Artifact.valid(".exe") || m.Updater.ProtocolVersion != 1 || m.MSI.Artifact.File == m.Updater.Artifact.File {
		return false
	}
	if !orderedVersions(c.MinimumAgentVersion, c.MaximumAgentVersion) || c.ManagementMin == 0 || c.ManagementMax < c.ManagementMin || c.ManagementMax > 64 || c.DesktopMin == 0 || c.DesktopMax < c.DesktopMin || c.DesktopMax > 64 {
		return false
	}
	if (m.RebootPolicy != "never" && m.RebootPolicy != "may-require") || m.RollbackPredecessors == nil || len(m.RollbackPredecessors) > 16 {
		return false
	}
	if d := m.Driver; d != nil {
		if _, ok := version(d.Version, 4); !ok || !d.Artifact.valid(".zip") || !validDigest(d.SignerSHA256) || len(d.HardwareIDs) == 0 || len(d.HardwareIDs) > 8 {
			return false
		}
		seen := map[string]bool{}
		for _, id := range d.HardwareIDs {
			lower := strings.ToLower(id)
			if !hardwareID.MatchString(id) || !strings.Contains(id, `\`) || seen[lower] {
				return false
			}
			seen[lower] = true
		}
	}
	ids, digests := map[string]bool{}, map[string]bool{}
	for _, p := range m.RollbackPredecessors {
		if !identifier.MatchString(p.TargetID) || p.TargetID == m.TargetID || !validDigest(p.ManifestSHA256) || ids[p.TargetID] || digests[p.ManifestSHA256] {
			return false
		}
		ids[p.TargetID], digests[p.ManifestSHA256] = true, true
	}
	return true
}

// encoding/json matches field names case-insensitively and allows null for
// required scalars. Validate exact wire names and required-object/array presence
// against the tagged schema so Go cannot accept a body the Rust verifier rejects.
func exactFields(raw []byte, typ reflect.Type) error {
	if typ.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil
		}
		return exactFields(raw, typ.Elem())
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil {
			return ErrInvalid
		}
		allowed := map[string]bool{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")
			allowed[tag[0]] = true
			value, present := fields[tag[0]]
			if !present {
				if len(tag) < 2 || tag[1] != "omitempty" {
					return ErrInvalid
				}
				continue
			}
			if err := exactFields(value, field.Type); err != nil {
				return err
			}
		}
		for key := range fields {
			if !allowed[key] {
				return ErrInvalid
			}
		}
	case reflect.Slice:
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil || items == nil {
			return ErrInvalid
		}
		for _, item := range items {
			if err := exactFields(item, typ.Elem()); err != nil {
				return err
			}
		}
	default:
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return ErrInvalid
		}
	}
	return nil
}

// Go's JSON decoder otherwise accepts duplicate object keys (including escaped
// aliases). Rust's derived struct decoder rejects them. Walk every nested object
// first, bounded by the manifest length and a depth much greater than schema v1.
func uniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return ErrInvalid
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return err
					}
					s, ok := key.(string)
					if !ok || seen[s] {
						return ErrInvalid
					}
					seen[s] = true
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			default:
				return ErrInvalid
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}
