package updates

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"
)

// InventoryDomain frames authenticated management.inventory.v1 reports. The
// signature covers the domain plus the exact payload bytes; freshness and the
// server-minted nonce binding are checked after authenticity.
const (
	InventoryDomain        = "kw-management-inventory/v1\x00"
	MaxInventoryBytes      = 32 * 1024
	InventoryFreshSeconds  = 60
	MaxInventoryMSIEntries = 8
)

var (
	ErrInventory      = errors.New("invalid machine inventory")
	ErrInventoryFresh = errors.New("machine inventory is stale, future-dated or bound to a different nonce")
	packageIdentity   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

type InventoryMSI struct {
	ProductCode      string `json:"product_code"`
	UpgradeCode      string `json:"upgrade_code"`
	Version          string `json:"version"`
	InstallDirectory string `json:"install_directory"`
}

type InventoryDriver struct {
	PackageIdentity string `json:"package_identity"`
	PackageSHA256   string `json:"package_sha256"`
	InfName         string `json:"inf_name"`
	DeviceInstance  string `json:"device_instance"`
	DriverVersion   string `json:"driver_version"`
}

type InventoryAttempt struct {
	AttemptID string `json:"attempt_id"`
	Phase     string `json:"phase"`
	Sequence  uint64 `json:"sequence"`
}

// Inventory is the authenticated machine report. The exact bytes are digested
// into expected_installed_inventory_sha256 at start; a report is evidence, not
// upgrade authority.
type Inventory struct {
	Version         uint32            `json:"version"`
	Nonce           string            `json:"nonce"`
	Timestamp       int64             `json:"timestamp"`
	Namespace       string            `json:"namespace"`
	Name            string            `json:"name"`
	WorkspaceUID    string            `json:"workspace_uid"`
	VMUID           string            `json:"vm_uid"`
	RevocationEpoch uint64            `json:"revocation_epoch"`
	OS              string            `json:"os"`
	Architecture    string            `json:"architecture"`
	AgentVersion    string            `json:"agent_version"`
	BuildSHA256     string            `json:"build_sha256"`
	ManagementMin   uint16            `json:"management_min"`
	ManagementMax   uint16            `json:"management_max"`
	UpdaterMin      uint16            `json:"updater_min"`
	UpdaterMax      uint16            `json:"updater_max"`
	MSI             []InventoryMSI    `json:"msi"`
	Driver          *InventoryDriver  `json:"driver"`
	PendingReboot   bool              `json:"pending_reboot"`
	Attempt         *InventoryAttempt `json:"attempt"`
}

type VerifiedInventory struct {
	inventory Inventory
	digest    string
}

// VerifyInventory requires the independently minted nonce and current time in
// addition to a pinned agent identity keyring. Every string field is
// ASCII-bounded so the canonical re-encode matches serde_json byte for byte.
func VerifyInventory(raw, signature []byte, keyID, expectedNonce string, now int64, keys map[string]ed25519.PublicKey) (*VerifiedInventory, error) {
	if len(raw) == 0 || len(raw) > MaxInventoryBytes || !utf8.Valid(raw) {
		return nil, ErrInventory
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
	if !ed25519.Verify(public, append([]byte(InventoryDomain), raw...), signature) {
		return nil, ErrSignature
	}
	if err := uniqueJSON(raw); err != nil {
		return nil, ErrInventory
	}
	if err := exactFields(raw, reflect.TypeOf(Inventory{})); err != nil {
		return nil, ErrInventory
	}
	var inventory Inventory
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&inventory) != nil || decoder.Decode(new(interface{})) != io.EOF || !inventory.valid() {
		return nil, ErrInventory
	}
	if !bytes.Equal(inventory.Encode(), raw) {
		return nil, ErrInventory
	}
	if !validNonce(inventory.Nonce) || inventory.Nonce != expectedNonce {
		return nil, ErrInventoryFresh
	}
	if now < inventory.Timestamp || now-inventory.Timestamp > InventoryFreshSeconds {
		return nil, ErrInventoryFresh
	}
	return &VerifiedInventory{inventory: inventory, digest: Digest(raw)}, nil
}

func (v *VerifiedInventory) SHA256() string { return v.digest }

// Metadata returns a deep copy so availability callers cannot mutate the
// verified report behind the digest.
func (v *VerifiedInventory) Metadata() Inventory {
	i := v.inventory
	i.MSI = append([]InventoryMSI{}, v.inventory.MSI...)
	if i.Driver != nil {
		d := *i.Driver
		i.Driver = &d
	}
	if i.Attempt != nil {
		a := *i.Attempt
		i.Attempt = &a
	}
	return i
}

// Encode reproduces the exact signed bytes. SetEscapeHTML(false) keeps the
// output byte-identical to serde_json for the ASCII-only schema, including
// install directories containing '&'.
func (i Inventory) Encode() []byte {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(i); err != nil {
		panic("inventory schema serialization is infallible")
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})
}

func validNonce(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == s
}

func validInstallDirectory(s string) bool {
	if len(s) == 0 || len(s) > 260 {
		return false
	}
	for _, b := range []byte(s) {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

func validInfName(s string) bool {
	if !identifier.MatchString(s) || strings.HasSuffix(s, ".") || !strings.HasSuffix(s, ".inf") {
		return false
	}
	stem := strings.SplitN(s, ".", 2)[0]
	if stem == "con" || stem == "prn" || stem == "aux" || stem == "nul" {
		return false
	}
	return len(stem) != 4 || (!strings.HasPrefix(stem, "com") && !strings.HasPrefix(stem, "lpt")) || stem[3] < '1' || stem[3] > '9'
}

func validJournalPhase(s string) bool {
	switch s {
	case "ready", "active", "awaiting_reboot", "rollback_pending", "result_pending", "terminal":
		return true
	}
	return false
}

func (i Inventory) valid() bool {
	if i.Version != 1 || !validNonce(i.Nonce) || i.Timestamp <= 0 || i.RevocationEpoch > math.MaxInt64 {
		return false
	}
	if !identifier.MatchString(i.Namespace) || !identifier.MatchString(i.Name) || !identifier.MatchString(i.WorkspaceUID) || !identifier.MatchString(i.VMUID) {
		return false
	}
	if i.OS != "windows" || i.Architecture != "amd64" {
		return false
	}
	if _, ok := version(i.AgentVersion, 3); !ok || !validDigest(i.BuildSHA256) {
		return false
	}
	if i.ManagementMin == 0 || i.ManagementMax < i.ManagementMin || i.ManagementMax > 64 || i.UpdaterMin == 0 || i.UpdaterMax < i.UpdaterMin || i.UpdaterMax > 64 {
		return false
	}
	if len(i.MSI) == 0 || len(i.MSI) > MaxInventoryMSIEntries {
		return false
	}
	agent, products := 0, map[string]bool{}
	for _, m := range i.MSI {
		if !guid.MatchString(m.ProductCode) || m.ProductCode == "00000000-0000-0000-0000-000000000000" || !guid.MatchString(m.UpgradeCode) || m.ProductCode == m.UpgradeCode || products[m.ProductCode] {
			return false
		}
		products[m.ProductCode] = true
		if _, ok := version(m.Version, 3); !ok || !validInstallDirectory(m.InstallDirectory) {
			return false
		}
		if m.UpgradeCode == AgentUpgradeCode {
			agent++
		}
	}
	if agent != 1 {
		return false
	}
	if d := i.Driver; d != nil {
		if !packageIdentity.MatchString(d.PackageIdentity) || !validDigest(d.PackageSHA256) || !validInfName(d.InfName) || !hardwareID.MatchString(d.DeviceInstance) || !strings.Contains(d.DeviceInstance, `\`) {
			return false
		}
		if _, ok := version(d.DriverVersion, 4); !ok {
			return false
		}
	}
	if a := i.Attempt; a != nil {
		if !identifier.MatchString(a.AttemptID) || !validJournalPhase(a.Phase) || a.Sequence > MaxJournalSequence {
			return false
		}
	}
	return true
}
