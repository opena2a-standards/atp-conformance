// Package main is the Go reference verifier for the ATP v1.0.0-rc1
// conformance fixture set. It depends only on the Go standard library plus
// github.com/cloudflare/circl (for ML-DSA-65 verification per FIPS 204).
//
// It does NOT import any opena2a-* SDK or registry package. The goal is to
// validate that the conformance fixtures are byte-stable and that an
// independent verifier with only the spec and the public keypair vectors can
// reproduce ACCEPT / REJECT for every fixture.
//
// Spec it implements:
//   - ATP v1.0.0-rc1 §4.4 trust proof verification (Steps 1-5)
//   - ATP §4.3 canonical pipe-delimited 7-field signing form
//   - ATP §5.6 Signed Tree Head verification (Ed25519 over raw rootHash bytes)
//   - ATP §7.1 well-known discovery structural verification
//   - ATP §4.3 hybrid Ed25519 + ML-DSA-65 (FIPS 204) signing path
//
// Usage:
//
//	go run github.com/opena2a-standards/atp-conformance/verifiers/go@latest
//	go run .                             (no arguments; the built-in fixture set)
//	go run . ../../fixtures/trust-proof-baseline.json
//	go run . ../../fixtures/*.json
//	go run . ../../fixtures              (directory; walks *.json)
//	go run . ../..                       (repo root; walks fixtures/*.json)
//
// With no arguments it verifies the fixture set built into the binary: the
// fixtures/ directory next to this file, a byte copy of the repository's
// fixtures/. That is what lets the first form above run the suite without a
// clone. scripts/parity/parity.py fails when the copy and fixtures/ differ.
//
// Exit 0 iff every fixture's observed result matches expected.verifyResult.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// builtinFixtures is the fixture set a run with no arguments verifies.
//
//go:embed fixtures/*.json
var builtinFixtures embed.FS

// ---------------------------------------------------------------------------
// fixture shape (mirror of generator)
// ---------------------------------------------------------------------------

type fixture struct {
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	FixtureType   string          `json:"fixtureType"`
	KeypairRefs   []keypairRef    `json:"keypairRefs"`
	VerifierState verifierState   `json:"verifierState"`
	Expected      expectedOutcome `json:"expected"`
	// The payload members stay raw here and are decoded by the per-type
	// verifier through decodePayload, so a member whose JSON type or range
	// does not fit its struct is a REJECT[PARSE_ERROR] verdict on the
	// fixture rather than a load error with no verdict.
	DiscoveryResponse json.RawMessage `json:"discoveryResponse,omitempty"`
	TrustProof        json.RawMessage `json:"trustProof,omitempty"`
	SignedTreeHead    json.RawMessage `json:"signedTreeHead,omitempty"`
	InclusionProof    json.RawMessage `json:"inclusionProof,omitempty"`
	ConsistencyProof  json.RawMessage `json:"consistencyProof,omitempty"`
	RevocationList    json.RawMessage `json:"revocationList,omitempty"`
}

// inclusionProof mirrors ATP §5.4 (see the generator for the wire contract).
type inclusionProof struct {
	LogIndex       int64           `json:"logIndex"`
	LeafHash       string          `json:"leafHash"`
	AuditPath      []string        `json:"auditPath"`
	SignedTreeHead *signedTreeHead `json:"signedTreeHead"`
}

// consistencyProof mirrors ATP §5.5.
type consistencyProof struct {
	FromSize           int64           `json:"fromSize"`
	ToSize             int64           `json:"toSize"`
	ConsistencyPath    []string        `json:"consistencyPath"`
	FromSignedTreeHead *signedTreeHead `json:"fromSignedTreeHead"`
	ToSignedTreeHead   *signedTreeHead `json:"toSignedTreeHead"`
}

// revocationList mirrors ATP §8.1.
type revocationList struct {
	Revocations []revocationEntry `json:"revocations"`
	NextSince   string            `json:"nextSince"`
}

type revocationEntry struct {
	AgentDID  string `json:"agentDid"`
	RevokedAt string `json:"revokedAt"`
	Reason    string `json:"reason"`
	// TransparencyLogIndex is optional. A pointer keeps an absent or null
	// member (nil) apart from index 0, so only a present index is checked.
	TransparencyLogIndex *int64 `json:"transparencyLogIndex"`
	RevokedByKeyID       string `json:"revokedByKeyId"`
}

type keypairRef struct {
	Role         string `json:"role"`
	Path         string `json:"path"`
	Algorithm    string `json:"algorithm"`
	PublicKeyHex string `json:"publicKeyHex"`
	KeyID        string `json:"keyId"`
}

type verifierState struct {
	ClockRFC3339   string       `json:"clockRfc3339"`
	TrustedIssuers []string     `json:"trustedIssuers"`
	PublicKeys     []keypairRef `json:"publicKeys"`
}

type expectedOutcome struct {
	VerifyResult   string `json:"verifyResult"`
	RejectCategory string `json:"rejectCategory,omitempty"`
	ReasonContains string `json:"reasonContains,omitempty"`
}

type discoveryResponse struct {
	AuthorityDID     string               `json:"authorityDid"`
	Version          string               `json:"version"`
	ConformanceLevel int                  `json:"conformanceLevel"`
	Endpoints        map[string]string    `json:"endpoints"`
	PublicKeys       []discoveryPublicKey `json:"publicKeys"`
	SupportedMethods []string             `json:"supportedMethods"`
	Capabilities     []string             `json:"capabilities"`
}

type discoveryPublicKey struct {
	KeyID        string `json:"keyId"`
	Algorithm    string `json:"algorithm"`
	PublicKeyHex string `json:"publicKeyHex"`
	Status       string `json:"status"`
	ValidFrom    string `json:"validFrom"`
}

type proofSignature struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type trustProof struct {
	DID                  string           `json:"did"`
	TrustLevel           int              `json:"trustLevel"`
	TrustScore           float64          `json:"trustScore"`
	Verdict              string           `json:"verdict"`
	IssuedAt             string           `json:"issuedAt"`
	ExpiresAt            string           `json:"expiresAt"`
	IssuerDID            string           `json:"issuerDid"`
	Signatures           []proofSignature `json:"signatures"`
	TransparencyLogIndex *int64           `json:"transparencyLogIndex,omitempty"` // optional, as on a §8.1 entry: nil when absent or null
}

type signedTreeHead struct {
	TreeSize  int64  `json:"treeSize"`
	Timestamp string `json:"timestamp"`
	RootHash  string `json:"rootHash"`
	SignedBy  string `json:"signedBy"`
	Signature string `json:"signature"`
}

// ---------------------------------------------------------------------------
// canonicalization (mirror of generator VERBATIM)
// ---------------------------------------------------------------------------

func canonicalProofPayload(p *trustProof) []byte {
	return []byte(fmt.Sprintf("%s|%d|%.6f|%s|%s|%s|%s",
		p.DID,
		p.TrustLevel,
		p.TrustScore,
		p.Verdict,
		normalizeRFC3339(p.IssuedAt),
		normalizeRFC3339(p.ExpiresAt),
		p.IssuerDID,
	))
}

func sthSignedBytes(rootHash string) ([]byte, error) {
	stripped := strings.TrimPrefix(rootHash, "SHA256:")
	raw, err := hex.DecodeString(stripped)
	if err != nil {
		return nil, fmt.Errorf("rootHash hex decode: %w", err)
	}
	if len(raw) != sha256.Size {
		return nil, fmt.Errorf("rootHash must decode to %d bytes, got %d", sha256.Size, len(raw))
	}
	return raw, nil
}

func normalizeRFC3339(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.UTC().Format(time.RFC3339)
}

// ---------------------------------------------------------------------------
// verification result
// ---------------------------------------------------------------------------

type result struct {
	Accepted       bool
	RejectCategory string
	Reason         string
	Ed25519Valid   bool
	MLDSA65Valid   bool
	SigsExpected   int
	SigsValid      int
}

func (r result) String() string {
	if r.Accepted {
		return "ACCEPT"
	}
	return fmt.Sprintf("REJECT[%s: %s]", r.RejectCategory, r.Reason)
}

// ---------------------------------------------------------------------------
// payload decoding
// ---------------------------------------------------------------------------

// decodePayload decodes one payload member into the wire struct the
// verifier reads. An absent or null payload decodes to nil. A member whose
// JSON does not fit the struct (a string where the schema says integer, a
// number with a fraction or exponent in an integer member, an int64
// overflow, an array where a string is expected, a null where the struct
// has no pointer) yields a non-empty PARSE_ERROR reason naming the member,
// so the verdict matches the Python verifier instead of surfacing as a load
// error. So does a member name that a JSON object in the payload repeats:
// repeatedMember walks the payload before it is decoded. The struct types
// are the schema's: int / int64 for integer, float64 for number, string for
// string. A member is read by its exact name (exactMembers).
func decodePayload[T any](label string, raw json.RawMessage) (*T, string) {
	if len(raw) == 0 {
		return nil, ""
	}
	if member := repeatedMember(label, raw, nil); member != "" {
		return nil, member + ": duplicate member name"
	}
	raw = exactMembers(raw, reflect.TypeOf((*T)(nil)).Elem())
	var out *T
	if err := json.Unmarshal(raw, &out); err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			member := label
			if typeErr.Field != "" {
				member += "." + typeErr.Field
			}
			return nil, fmt.Sprintf("%s: JSON %s does not fit the %s the schema requires", member, typeErr.Value, schemaWord(typeErr.Type))
		}
		return nil, label + ": " + err.Error()
	}
	if out != nil {
		if member, t := nullMember(label, raw, reflect.TypeOf(out).Elem()); member != "" {
			return nil, fmt.Sprintf("%s: JSON null does not fit the %s the schema requires", member, schemaWord(t))
		}
	}
	return out, ""
}

// nullMember walks raw along the decode target t (struct fields in
// declaration order, array elements in order, map keys sorted) and returns
// the first member that is JSON null where t is not a pointer, with that
// member's type; "" when there is none. encoding/json decodes such a null
// silently to the zero value, which would read revocations null as an empty
// revocation list. JSON null is a value of no schema type, so it is rejected
// like any other wrong type. A pointer member (an optional
// transparencyLogIndex, an embedded tree head) takes null as absent and the
// verification steps judge it. Members are named the way the Python
// verifier's _decode names them: object.member and array[index].
func nullMember(label string, raw json.RawMessage, t reflect.Type) (string, reflect.Type) {
	isNull := strings.TrimSpace(string(raw)) == "null"
	if t.Kind() == reflect.Pointer {
		if isNull {
			return "", nil
		}
		return nullMember(label, raw, t.Elem())
	}
	if isNull {
		return label, t
	}
	switch t.Kind() {
	case reflect.Struct:
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) != nil {
			return "", nil
		}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			name, decoded := memberName(field)
			value, present := members[name]
			if !present || !decoded {
				continue
			}
			if member, mt := nullMember(label+"."+name, value, field.Type); member != "" {
				return member, mt
			}
		}
	case reflect.Slice:
		var elems []json.RawMessage
		if json.Unmarshal(raw, &elems) != nil {
			return "", nil
		}
		for i, elem := range elems {
			if member, mt := nullMember(fmt.Sprintf("%s[%d]", label, i), elem, t.Elem()); member != "" {
				return member, mt
			}
		}
	case reflect.Map:
		var values map[string]json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return "", nil
		}
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if member, mt := nullMember(label+"."+key, values[key], t.Elem()); member != "" {
				return member, mt
			}
		}
	}
	return "", nil
}

// memberName is the JSON member name encoding/json decodes into field, and
// whether it decodes into field at all.
func memberName(field reflect.StructField) (string, bool) {
	name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	if name == "" {
		name = field.Name
	}
	return name, field.IsExported() && name != "-"
}

// rawMessageType is the type of a fixture's payload members, which stay raw
// until decodePayload decodes them.
var rawMessageType = reflect.TypeOf(json.RawMessage(nil))

// exactMembers returns raw with each member of an object that decodes into
// a struct left out unless its name is exactly the JSON name of one of the
// struct's fields, walking raw along the decode target t (pointers, struct
// fields, array elements, map values). encoding/json matches a member name
// to a field case-insensitively, so on its own it decodes TreeSize,
// treesize or "tree\U0000017fize" (U+017F folds to S) as treeSize. JSON
// member names are case-sensitive and the Python verifier's _decode reads
// each member by its exact name, so in both verifiers such a member is not
// the schema member, which is then absent. A map key is data, not a member
// name, and is kept. The members kept stay in document order, repeated
// names included. A value that is not the JSON type t needs is returned
// unchanged, for the decode to reject.
func exactMembers(raw json.RawMessage, t reflect.Type) json.RawMessage {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == rawMessageType {
		return raw
	}
	switch t.Kind() {
	case reflect.Struct:
		members, ok := objectMembers(raw)
		if !ok {
			return raw
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			if name, decoded := memberName(t.Field(i)); decoded {
				fields[name] = t.Field(i).Type
			}
		}
		var kept []objectMember
		for _, m := range members {
			if ft, ok := fields[m.name]; ok {
				kept = append(kept, objectMember{m.name, exactMembers(m.value, ft)})
			}
		}
		return encodeObject(kept)
	case reflect.Map:
		members, ok := objectMembers(raw)
		if !ok {
			return raw
		}
		for i := range members {
			members[i].value = exactMembers(members[i].value, t.Elem())
		}
		return encodeObject(members)
	case reflect.Slice:
		elems, ok := arrayElements(raw)
		if !ok {
			return raw
		}
		out := []byte{'['}
		for i, elem := range elems {
			if i > 0 {
				out = append(out, ',')
			}
			out = append(out, exactMembers(elem, t.Elem())...)
		}
		return append(out, ']')
	}
	return raw
}

// objectMember is one member of a JSON object: its name and its raw value.
type objectMember struct {
	name  string
	value json.RawMessage
}

// objectMembers returns the members of raw in document order, repeated
// names included, when raw is a JSON object.
func objectMembers(raw json.RawMessage) ([]objectMember, bool) {
	if !json.Valid(raw) {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	var members []objectMember
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		name, _ := tok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, false
		}
		members = append(members, objectMember{name, value})
	}
	return members, true
}

// encodeObject writes members as a JSON object, in order.
func encodeObject(members []objectMember) json.RawMessage {
	out := []byte{'{'}
	for i, m := range members {
		if i > 0 {
			out = append(out, ',')
		}
		name, _ := json.Marshal(m.name)
		out = append(out, name...)
		out = append(out, ':')
		out = append(out, m.value...)
	}
	return append(out, '}')
}

// arrayElements returns the elements of raw when it is a JSON array.
func arrayElements(raw json.RawMessage) ([]json.RawMessage, bool) {
	var elems []json.RawMessage
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '[' || json.Unmarshal(raw, &elems) != nil {
		return nil, false
	}
	return elems, true
}

// payloadMembers are the fixture members decodePayload decodes: the protocol
// response under test. A repeated member name inside one is a PARSE_ERROR
// verdict on the fixture; elsewhere in the fixture document it is a load
// error (parseFixture). The Python verifier's _PAYLOAD_MEMBERS holds the same
// names.
var payloadMembers = map[string]bool{
	"discoveryResponse": true,
	"trustProof":        true,
	"signedTreeHead":    true,
	"inclusionProof":    true,
	"consistencyProof":  true,
	"revocationList":    true,
}

// repeatedMember returns the first member name, in document order, that a
// JSON object in raw repeats, named the way nullMember names members
// (object.member, array[index]; a top-level member with an empty label is
// its bare name), or "" when no object repeats a name. RFC 8259 §4 leaves a
// repeated name's meaning to the receiver, and the two verifiers' decoders
// read it differently: encoding/json decodes the occurrences into the same
// field one after another, so the members of an earlier object occurrence
// survive and the first type error is the one reported, where Python's
// json.loads keeps only the last occurrence. Both verifiers refuse such a
// document instead, as RFC 7493 §2.3 requires of I-JSON, so neither
// verifies its own reading of it. The value of a member whose path is in
// skip is not walked. raw is valid JSON: it comes from a document
// json.Unmarshal has accepted.
func repeatedMember(label string, raw []byte, skip map[string]bool) string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Without UseNumber, Token stops with an error at a number such as 1e400
	// that does not fit a float64, and a repeat after it would go unseen.
	dec.UseNumber()
	member, _ := walkMembers(dec, label, skip)
	return member
}

// walkMembers reads the next JSON value from dec for repeatedMember and
// returns the first repeated member in it.
func walkMembers(dec *json.Decoder, label string, skip map[string]bool) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			if tok, err = dec.Token(); err != nil {
				return "", err
			}
			name, _ := tok.(string)
			path := name
			if label != "" {
				path = label + "." + name
			}
			if seen[name] {
				return path, nil
			}
			seen[name] = true
			if skip[path] {
				var value json.RawMessage
				err = dec.Decode(&value)
			} else {
				var member string
				if member, err = walkMembers(dec, path, skip); member != "" {
					return member, nil
				}
			}
			if err != nil {
				return "", err
			}
		}
	case json.Delim('['):
		for i := 0; dec.More(); i++ {
			if member, err := walkMembers(dec, fmt.Sprintf("%s[%d]", label, i), skip); member != "" || err != nil {
				return member, err
			}
		}
	default:
		return "", nil
	}
	_, err = dec.Token() // the closing } or ]
	return "", err
}

// schemaWord names a decode target type in the vendored schemas' words.
func schemaWord(t reflect.Type) string {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Slice, reflect.Array:
		return "array"
	default:
		return "object"
	}
}

// ---------------------------------------------------------------------------
// per-type verifiers
// ---------------------------------------------------------------------------

func verifyDiscovery(f fixture) result {
	d, parseErr := decodePayload[discoveryResponse]("discoveryResponse", f.DiscoveryResponse)
	if parseErr != "" {
		return result{RejectCategory: "PARSE_ERROR", Reason: parseErr}
	}
	if d == nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "discoveryResponse missing"}
	}

	// ATP §7.1 required fields: authorityDid, version, endpoints, publicKeys.
	if d.AuthorityDID == "" {
		return result{RejectCategory: "DISCOVERY_INVALID", Reason: "authorityDid missing"}
	}
	if d.Version == "" {
		return result{RejectCategory: "DISCOVERY_INVALID", Reason: "version missing"}
	}
	if d.Version != "1.0" {
		return result{RejectCategory: "UNSUPPORTED_VERSION", Reason: fmt.Sprintf("unsupported atp version %q (this verifier supports 1.0)", d.Version)}
	}
	if d.ConformanceLevel < 1 || d.ConformanceLevel > 3 {
		return result{RejectCategory: "DISCOVERY_INVALID", Reason: fmt.Sprintf("conformanceLevel %d out of range [1,3]", d.ConformanceLevel)}
	}
	if len(d.Endpoints) == 0 {
		return result{RejectCategory: "DISCOVERY_INVALID", Reason: "endpoints missing"}
	}
	if len(d.PublicKeys) == 0 {
		return result{RejectCategory: "DISCOVERY_INVALID", Reason: "publicKeys missing"}
	}

	// authorityDid trust.
	trusted := false
	for _, did := range f.VerifierState.TrustedIssuers {
		if did == d.AuthorityDID {
			trusted = true
			break
		}
	}
	if !trusted {
		return result{
			RejectCategory: "UNTRUSTED_ISSUER",
			Reason:         "authority DID " + d.AuthorityDID + " is not in the verifier's trusted set",
		}
	}

	// publicKeys structural validation.
	for i, pk := range d.PublicKeys {
		switch pk.Algorithm {
		case "Ed25519":
			raw, err := hex.DecodeString(pk.PublicKeyHex)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				return result{
					RejectCategory: "DISCOVERY_INVALID",
					Reason:         fmt.Sprintf("publicKeys[%d] Ed25519 publicKeyHex invalid (need %d bytes)", i, ed25519.PublicKeySize),
				}
			}
		case "ML-DSA-65":
			raw, err := hex.DecodeString(pk.PublicKeyHex)
			if err != nil {
				return result{RejectCategory: "DISCOVERY_INVALID", Reason: fmt.Sprintf("publicKeys[%d] ML-DSA-65 publicKeyHex invalid hex", i)}
			}
			tmp := new(mldsa65.PublicKey)
			if err := tmp.UnmarshalBinary(raw); err != nil {
				return result{RejectCategory: "DISCOVERY_INVALID", Reason: fmt.Sprintf("publicKeys[%d] ML-DSA-65 publicKey unmarshal: %v", i, err)}
			}
		default:
			return result{RejectCategory: "DISCOVERY_INVALID", Reason: fmt.Sprintf("publicKeys[%d] unsupported algorithm %q", i, pk.Algorithm)}
		}
		if pk.Status != "active" && pk.Status != "retired" && pk.Status != "revoked" {
			return result{RejectCategory: "DISCOVERY_INVALID", Reason: fmt.Sprintf("publicKeys[%d] status %q not in {active,retired,revoked}", i, pk.Status)}
		}
	}

	return result{Accepted: true}
}

func verifyTrustProof(f fixture) result {
	tp, parseErr := decodePayload[trustProof]("trustProof", f.TrustProof)
	if parseErr != "" {
		return result{RejectCategory: "PARSE_ERROR", Reason: parseErr}
	}
	if tp == nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "trustProof missing"}
	}
	// transparencyLogIndex sits outside the §4.3 signed form and is not read
	// here, but the schema says integer, minimum 0: a negative index is a
	// malformed proof, not a proof to verify. The member is optional, so an
	// absent or null index is not checked.
	if tp.TransparencyLogIndex != nil && *tp.TransparencyLogIndex < 0 {
		return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("trustProof.transparencyLogIndex %d must be >= 0", *tp.TransparencyLogIndex)}
	}

	now, err := time.Parse(time.RFC3339, f.VerifierState.ClockRFC3339)
	if err != nil {
		return result{RejectCategory: "VERIFIER_CONFIG_ERROR", Reason: "bad clockRfc3339: " + err.Error()}
	}
	now = now.UTC()

	// ATP §4.4 Step 1: expiry.
	expires, err := time.Parse(time.RFC3339, tp.ExpiresAt)
	if err != nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "bad expiresAt: " + err.Error()}
	}
	if now.After(expires.UTC()) {
		return result{
			RejectCategory: "EXPIRED",
			Reason:         fmt.Sprintf("expired at %s, verifier clock is %s", expires.UTC().Format(time.RFC3339), now.Format(time.RFC3339)),
		}
	}

	// ATP §4.4 Step 2: issuer trust.
	trusted := false
	for _, did := range f.VerifierState.TrustedIssuers {
		if did == tp.IssuerDID {
			trusted = true
			break
		}
	}
	if !trusted {
		return result{
			RejectCategory: "UNTRUSTED_ISSUER",
			Reason:         "issuer DID " + tp.IssuerDID + " is not in the verifier's trusted set",
		}
	}

	// ATP §4.4 Step 5 semantic validation (early — these are cheap).
	if tp.TrustLevel < 0 || tp.TrustLevel > 4 {
		return result{RejectCategory: "SEMANTIC_INVALID", Reason: fmt.Sprintf("trustLevel %d out of range [0,4]", tp.TrustLevel)}
	}
	if tp.TrustScore < 0.0 || tp.TrustScore > 1.0 {
		return result{RejectCategory: "SEMANTIC_INVALID", Reason: fmt.Sprintf("trustScore %.6f out of range [0.0,1.0]", tp.TrustScore)}
	}
	if !validVerdict(tp.Verdict) {
		return result{RejectCategory: "SEMANTIC_INVALID", Reason: "verdict " + tp.Verdict + " not in {passed,warning,blocked,listed,verified,unknown}"}
	}
	issued, err := time.Parse(time.RFC3339, tp.IssuedAt)
	if err != nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "bad issuedAt: " + err.Error()}
	}
	if !issued.Before(expires) {
		return result{RejectCategory: "SEMANTIC_INVALID", Reason: "issuedAt must be before expiresAt"}
	}
	// ATP §4.4 step 5, §10.2 maximum: the declared window may not exceed
	// 24 hours. Exact comparison, no skew tolerance (§10.2: the skew bound
	// MUST NOT extend the 24-hour validity), whatever the verifier's clock.
	if expires.Sub(issued) > 24*time.Hour {
		return result{RejectCategory: "SEMANTIC_INVALID", Reason: "validity window exceeds 24 hours"}
	}

	// ATP §4.4 Steps 3-4: key lookup + signature verification.
	// Spec mandate (§4.3 paragraph 2): in hybrid mode BOTH signatures MUST verify.
	// We enforce: each declared signature MUST verify against some configured key
	// of the same algorithm; at least one valid Ed25519 signature is required.
	payload := canonicalProofPayload(tp)
	edKeys, pqKeys := indexPublicKeys(f.VerifierState.PublicKeys)
	res := result{SigsExpected: len(tp.Signatures)}

	for _, sig := range tp.Signatures {
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Value)
		if err != nil {
			return result{RejectCategory: "SIGNATURE_INVALID", Reason: fmt.Sprintf("signature %s has invalid base64: %v", sig.KeyID, err)}
		}
		switch sig.Algorithm {
		case "Ed25519":
			ok := false
			for _, pk := range edKeys {
				if ed25519.Verify(pk, payload, sigBytes) {
					ok = true
					break
				}
			}
			if !ok {
				return result{RejectCategory: "SIGNATURE_INVALID", Reason: fmt.Sprintf("Ed25519 signature %s did not verify against any configured public key", sig.KeyID)}
			}
			res.Ed25519Valid = true
			res.SigsValid++
		case "ML-DSA-65":
			ok := false
			for _, pk := range pqKeys {
				if mldsa65.Verify(pk, payload, nil, sigBytes) {
					ok = true
					break
				}
			}
			if !ok {
				return result{RejectCategory: "SIGNATURE_INVALID", Reason: fmt.Sprintf("ML-DSA-65 signature %s did not verify against any configured public key", sig.KeyID)}
			}
			res.MLDSA65Valid = true
			res.SigsValid++
		default:
			return result{RejectCategory: "SIGNATURE_INVALID", Reason: "unsupported signature algorithm " + sig.Algorithm}
		}
	}

	if !res.Ed25519Valid {
		return result{RejectCategory: "SIGNATURE_INVALID", Reason: "no valid Ed25519 signature (ATP §4.3 baseline)"}
	}

	res.Accepted = true
	return res
}

func verifySTH(f fixture) result {
	sth, parseErr := decodePayload[signedTreeHead]("signedTreeHead", f.SignedTreeHead)
	if parseErr != "" {
		return result{RejectCategory: "PARSE_ERROR", Reason: parseErr}
	}
	if sth == nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "signedTreeHead missing"}
	}

	if sth.TreeSize <= 0 {
		return result{RejectCategory: "STH_INVALID", Reason: fmt.Sprintf("treeSize %d must be > 0", sth.TreeSize)}
	}
	if _, err := time.Parse(time.RFC3339, sth.Timestamp); err != nil {
		return result{RejectCategory: "STH_INVALID", Reason: "bad timestamp: " + err.Error()}
	}
	rootBytes, err := sthSignedBytes(sth.RootHash)
	if err != nil {
		return result{RejectCategory: "STH_INVALID", Reason: err.Error()}
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sth.Signature)
	if err != nil {
		return result{RejectCategory: "SIGNATURE_INVALID", Reason: "STH signature has invalid base64: " + err.Error()}
	}

	edKeys, _ := indexPublicKeys(f.VerifierState.PublicKeys)
	for _, pk := range edKeys {
		if ed25519.Verify(pk, rootBytes, sigBytes) {
			return result{Accepted: true, Ed25519Valid: true, SigsExpected: 1, SigsValid: 1}
		}
	}
	return result{RejectCategory: "SIGNATURE_INVALID", Reason: "STH Ed25519 signature did not verify against any configured public key"}
}

// checkEmbeddedSTH validates a tree head embedded inside a §5.4/§5.5 proof
// payload — the same rules as verifySTH, factored so the proof verifiers and
// the standalone sth fixtureType stay behaviorally identical. Returns
// (category, reason); empty category means the head verifies.
func checkEmbeddedSTH(label string, sth *signedTreeHead, keys []keypairRef) (string, string) {
	if sth == nil {
		return "PARSE_ERROR", label + " missing"
	}
	if sth.TreeSize <= 0 {
		return "STH_INVALID", fmt.Sprintf("%s.treeSize %d must be > 0", label, sth.TreeSize)
	}
	if _, err := time.Parse(time.RFC3339, sth.Timestamp); err != nil {
		return "STH_INVALID", label + " bad timestamp: " + err.Error()
	}
	rootBytes, err := sthSignedBytes(sth.RootHash)
	if err != nil {
		return "STH_INVALID", label + ": " + err.Error()
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sth.Signature)
	if err != nil {
		return "SIGNATURE_INVALID", label + " signature has invalid base64: " + err.Error()
	}
	edKeys, _ := indexPublicKeys(keys)
	for _, pk := range edKeys {
		if ed25519.Verify(pk, rootBytes, sigBytes) {
			return "", ""
		}
	}
	return "SIGNATURE_INVALID", label + " Ed25519 signature did not verify against any configured public key"
}

// ---------------------------------------------------------------------------
// RFC 6962 Merkle verification (ATP §5.4/§5.5)
//
// leaf = SHA-256(0x00 || entry), node = SHA-256(0x01 || left || right).
// Verification follows RFC 9162 §2.1.3.2 (inclusion) and §2.1.4.2
// (consistency). Mirror VERBATIM in the Python verifier.
// ---------------------------------------------------------------------------

func merkleNodeHash(left, right [sha256.Size]byte) [sha256.Size]byte {
	buf := make([]byte, 0, 1+2*sha256.Size)
	buf = append(buf, 0x01)
	buf = append(buf, left[:]...)
	buf = append(buf, right[:]...)
	return sha256.Sum256(buf)
}

// wireHashBytes decodes a "SHA256:<64 lowercase hex>" wire hash.
func wireHashBytes(wire string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	stripped := strings.TrimPrefix(wire, "SHA256:")
	if stripped == wire {
		return out, fmt.Errorf("hash %q missing SHA256: prefix", wire)
	}
	raw, err := hex.DecodeString(stripped)
	if err != nil {
		return out, fmt.Errorf("hash %q is not hex: %v", wire, err)
	}
	if len(raw) != sha256.Size {
		return out, fmt.Errorf("hash %q must decode to %d bytes, got %d", wire, sha256.Size, len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// verifyMerkleInclusion checks an audit path per RFC 9162 §2.1.3.2.
func verifyMerkleInclusion(leafIndex, treeSize int64, leafHash [sha256.Size]byte, path [][sha256.Size]byte, root [sha256.Size]byte) bool {
	if leafIndex < 0 || treeSize < 1 || leafIndex >= treeSize {
		return false
	}
	fn, sn := leafIndex, treeSize-1
	r := leafHash
	for _, p := range path {
		if sn == 0 {
			return false
		}
		if fn%2 == 1 || fn == sn {
			r = merkleNodeHash(p, r)
			if fn%2 == 0 {
				for fn%2 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = merkleNodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && r == root
}

// verifyMerkleConsistency checks a consistency path per RFC 9162 §2.1.4.2.
func verifyMerkleConsistency(fromSize, toSize int64, path [][sha256.Size]byte, fromRoot, toRoot [sha256.Size]byte) bool {
	if fromSize < 1 || fromSize > toSize {
		return false
	}
	if fromSize == toSize {
		return len(path) == 0 && fromRoot == toRoot
	}
	full := path
	if fromSize&(fromSize-1) == 0 {
		full = append([][sha256.Size]byte{fromRoot}, path...)
	}
	if len(full) == 0 {
		return false
	}
	fn, sn := fromSize-1, toSize-1
	for fn%2 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := full[0], full[0]
	for _, c := range full[1:] {
		if sn == 0 {
			return false
		}
		if fn%2 == 1 || fn == sn {
			fr = merkleNodeHash(c, fr)
			sr = merkleNodeHash(c, sr)
			if fn%2 == 0 {
				for fn%2 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = merkleNodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && fr == fromRoot && sr == toRoot
}

// verifyInclusionProof implements ATP §5.4: the embedded tree head verifies
// per §5.6, then the RFC 9162 §2.1.3.2 recomputation from leafHash along
// auditPath must reproduce sth.rootHash.
func verifyInclusionProof(f fixture) result {
	ip, parseErr := decodePayload[inclusionProof]("inclusionProof", f.InclusionProof)
	if parseErr != "" {
		return result{RejectCategory: "PARSE_ERROR", Reason: parseErr}
	}
	if ip == nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "inclusionProof missing"}
	}

	leaf, err := wireHashBytes(ip.LeafHash)
	if err != nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "leafHash: " + err.Error()}
	}
	path := make([][sha256.Size]byte, len(ip.AuditPath))
	for i, p := range ip.AuditPath {
		path[i], err = wireHashBytes(p)
		if err != nil {
			return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("auditPath[%d]: %v", i, err)}
		}
	}
	if cat, reason := checkEmbeddedSTH("signedTreeHead", ip.SignedTreeHead, f.VerifierState.PublicKeys); cat != "" {
		return result{RejectCategory: cat, Reason: reason}
	}
	root, err := wireHashBytes(ip.SignedTreeHead.RootHash)
	if err != nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "rootHash: " + err.Error()}
	}
	if ip.LogIndex < 0 || ip.LogIndex >= ip.SignedTreeHead.TreeSize {
		return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("logIndex %d out of range for treeSize %d", ip.LogIndex, ip.SignedTreeHead.TreeSize)}
	}
	if !verifyMerkleInclusion(ip.LogIndex, ip.SignedTreeHead.TreeSize, leaf, path, root) {
		return result{RejectCategory: "PROOF_INVALID", Reason: "recomputed root from leafHash along auditPath does not equal signedTreeHead.rootHash"}
	}
	return result{Accepted: true, Ed25519Valid: true, SigsExpected: 1, SigsValid: 1}
}

// verifyConsistencyProof implements ATP §5.5: both embedded tree heads verify
// per §5.6, then the RFC 9162 §2.1.4.2 algorithm must reproduce both roots.
func verifyConsistencyProof(f fixture) result {
	cp, parseErr := decodePayload[consistencyProof]("consistencyProof", f.ConsistencyProof)
	if parseErr != "" {
		return result{RejectCategory: "PARSE_ERROR", Reason: parseErr}
	}
	if cp == nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "consistencyProof missing"}
	}

	if cp.FromSignedTreeHead == nil || cp.ToSignedTreeHead == nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "fromSignedTreeHead/toSignedTreeHead missing"}
	}
	if cp.FromSize != cp.FromSignedTreeHead.TreeSize || cp.ToSize != cp.ToSignedTreeHead.TreeSize {
		return result{RejectCategory: "PARSE_ERROR", Reason: "fromSize/toSize must equal the embedded tree heads' treeSize values"}
	}
	if cp.FromSize >= cp.ToSize {
		return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("fromSize %d must be < toSize %d", cp.FromSize, cp.ToSize)}
	}
	path := make([][sha256.Size]byte, len(cp.ConsistencyPath))
	var err error
	for i, p := range cp.ConsistencyPath {
		path[i], err = wireHashBytes(p)
		if err != nil {
			return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("consistencyPath[%d]: %v", i, err)}
		}
	}
	if cat, reason := checkEmbeddedSTH("fromSignedTreeHead", cp.FromSignedTreeHead, f.VerifierState.PublicKeys); cat != "" {
		return result{RejectCategory: cat, Reason: reason}
	}
	if cat, reason := checkEmbeddedSTH("toSignedTreeHead", cp.ToSignedTreeHead, f.VerifierState.PublicKeys); cat != "" {
		return result{RejectCategory: cat, Reason: reason}
	}
	fromRoot, err := wireHashBytes(cp.FromSignedTreeHead.RootHash)
	if err != nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "fromSignedTreeHead.rootHash: " + err.Error()}
	}
	toRoot, err := wireHashBytes(cp.ToSignedTreeHead.RootHash)
	if err != nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "toSignedTreeHead.rootHash: " + err.Error()}
	}
	if !verifyMerkleConsistency(cp.FromSize, cp.ToSize, path, fromRoot, toRoot) {
		return result{RejectCategory: "PROOF_INVALID", Reason: "consistencyPath does not connect fromSignedTreeHead.rootHash to toSignedTreeHead.rootHash (append-only claim broken)"}
	}
	return result{Accepted: true, Ed25519Valid: true, SigsExpected: 2, SigsValid: 2}
}

// verifyRevocationList implements ATP §8.1: structural verification of the
// unsigned revocation body. A malformed timestamp rejects the WHOLE response
// — a client that skips unparseable entries keeps trusting a revoked agent.
func verifyRevocationList(f fixture) result {
	rl, parseErr := decodePayload[revocationList]("revocationList", f.RevocationList)
	if parseErr != "" {
		return result{RejectCategory: "PARSE_ERROR", Reason: parseErr}
	}
	if rl == nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "revocationList missing"}
	}

	if rl.NextSince == "" {
		return result{RejectCategory: "PARSE_ERROR", Reason: "nextSince missing"}
	}
	if _, err := time.Parse(time.RFC3339, rl.NextSince); err != nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "nextSince is not RFC 3339: " + err.Error()}
	}
	for i, entry := range rl.Revocations {
		if entry.AgentDID == "" || !strings.HasPrefix(entry.AgentDID, "did:") {
			return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("revocations[%d].agentDid %q is not a DID", i, entry.AgentDID)}
		}
		if _, err := time.Parse(time.RFC3339, entry.RevokedAt); err != nil {
			return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("revocations[%d].revokedAt is not RFC 3339: %v", i, err)}
		}
		if entry.Reason == "" {
			return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("revocations[%d].reason missing", i)}
		}
		if entry.TransparencyLogIndex != nil && *entry.TransparencyLogIndex < 0 {
			return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("revocations[%d].transparencyLogIndex %d must be >= 0", i, *entry.TransparencyLogIndex)}
		}
		if !strings.Contains(entry.RevokedByKeyID, "#") {
			return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("revocations[%d].revokedByKeyId %q is not fragment-qualified", i, entry.RevokedByKeyID)}
		}
	}
	return result{Accepted: true}
}

func validVerdict(v string) bool {
	switch v {
	case "passed", "warning", "blocked", "listed", "verified", "unknown":
		return true
	}
	return false
}

func indexPublicKeys(refs []keypairRef) (eds []ed25519.PublicKey, pqs []*mldsa65.PublicKey) {
	for _, r := range refs {
		switch r.Algorithm {
		case "Ed25519":
			raw, err := hex.DecodeString(r.PublicKeyHex)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				continue
			}
			eds = append(eds, ed25519.PublicKey(raw))
		case "ML-DSA-65":
			raw, err := hex.DecodeString(r.PublicKeyHex)
			if err != nil {
				continue
			}
			pk := new(mldsa65.PublicKey)
			if err := pk.UnmarshalBinary(raw); err != nil {
				continue
			}
			pqs = append(pqs, pk)
		}
	}
	return
}

// ---------------------------------------------------------------------------
// driver
// ---------------------------------------------------------------------------

func verify(f fixture) result {
	switch f.FixtureType {
	case "discovery":
		return verifyDiscovery(f)
	case "trustProof":
		return verifyTrustProof(f)
	case "sth":
		return verifySTH(f)
	case "inclusionProof":
		return verifyInclusionProof(f)
	case "consistencyProof":
		return verifyConsistencyProof(f)
	case "revocationList":
		return verifyRevocationList(f)
	default:
		return result{RejectCategory: "PARSE_ERROR", Reason: "unknown fixtureType " + f.FixtureType}
	}
}

func main() {
	var (
		paths []string
		err   error
		load  = loadFixture
		show  = relPath
	)
	if len(os.Args) < 2 {
		paths, err = builtinFixturePaths()
		load, show = loadBuiltinFixture, func(p string) string { return p }
		if err == nil {
			fmt.Println(builtinHeader(len(paths)))
		}
	} else {
		paths, err = expandFixturePaths(os.Args[1:])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "no fixture *.json files found in supplied args")
		os.Exit(2)
	}

	if _, totalFail := verifyAll(os.Stdout, paths, load, show); totalFail > 0 {
		os.Exit(1)
	}
}

// builtinHeader names the fixture set a run with no arguments verifies: the
// module path and version this binary was built from, and how to verify
// other fixtures instead.
func builtinHeader(n int) string {
	from := "this binary"
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Path != "" {
		from = strings.TrimSpace(info.Main.Path + " " + info.Main.Version)
	}
	return fmt.Sprintf("verifying the %d fixtures built into %s\n"+
		"to verify other fixtures, pass their files or a directory as arguments\n", n, from)
}

// verifyAll verifies the fixture at each path, writes one block per fixture
// and the summary line to w, and returns the pass and fail counts. load reads
// a path and show formats it for output.
func verifyAll(w io.Writer, paths []string, load func(string) (fixture, error), show func(string) string) (totalPass, totalFail int) {
	for _, p := range paths {
		f, err := load(p)
		if err != nil {
			fmt.Fprintf(w, "FAIL  %s  (load error: %v)\n", show(p), err)
			totalFail++
			continue
		}
		got := verify(f)
		wantAccept := strings.EqualFold(f.Expected.VerifyResult, "ACCEPT")
		ok := (wantAccept && got.Accepted) || (!wantAccept && !got.Accepted)
		if ok && !wantAccept && f.Expected.RejectCategory != "" {
			if got.RejectCategory != f.Expected.RejectCategory {
				ok = false
			}
		}
		if ok && !wantAccept && f.Expected.ReasonContains != "" {
			if !strings.Contains(strings.ToLower(got.Reason), strings.ToLower(f.Expected.ReasonContains)) {
				ok = false
			}
		}
		status := "PASS"
		if !ok {
			status = "FAIL"
			totalFail++
		} else {
			totalPass++
		}
		fmt.Fprintf(w, "%s  %s  [%s]\n", status, show(p), f.FixtureType)
		fmt.Fprintf(w, "       expected: %s", f.Expected.VerifyResult)
		if f.Expected.RejectCategory != "" {
			fmt.Fprintf(w, " [%s]", f.Expected.RejectCategory)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "       observed: %s\n", got)
		if got.SigsExpected > 0 {
			fmt.Fprintf(w, "       signatures: %d/%d valid (ed25519=%t mldsa65=%t)\n",
				got.SigsValid, got.SigsExpected, got.Ed25519Valid, got.MLDSA65Valid)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "summary: %d pass, %d fail (%d fixtures)\n", totalPass, totalFail, totalPass+totalFail)
	return totalPass, totalFail
}

func loadFixture(path string) (fixture, error) {
	// path originates from os.Args[1:] (operator-supplied fixture file/dir); this is a
	// standalone CLI verifier with no network/request surface, so no untrusted taint.
	b, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied CLI arg, not request-derived
	if err != nil {
		return fixture{}, err
	}
	return parseFixture(b)
}

// builtinFixturePaths lists the fixture set built into the binary, sorted.
func builtinFixturePaths() ([]string, error) {
	paths, err := fs.Glob(builtinFixtures, "fixtures/*.json")
	sort.Strings(paths)
	return paths, err
}

// loadBuiltinFixture reads one fixture from the set built into the binary.
func loadBuiltinFixture(path string) (fixture, error) {
	b, err := builtinFixtures.ReadFile(path)
	if err != nil {
		return fixture{}, err
	}
	return parseFixture(b)
}

// parseFixture decodes a fixture document. Its members (fixtureType,
// verifierState, expected and the payload members) are read by their exact
// names, as decodePayload reads a payload's (exactMembers). A JSON object
// outside the payload members that repeats a member name is a load error:
// the verifier configuration or expected outcome it carries has no single
// reading. A repeat inside a payload member is a PARSE_ERROR verdict from
// decodePayload.
func parseFixture(b []byte) (fixture, error) {
	var f fixture
	if err := json.Unmarshal(exactMembers(b, reflect.TypeOf(f)), &f); err != nil {
		return fixture{}, err
	}
	if member := repeatedMember("", b, payloadMembers); member != "" {
		return fixture{}, fmt.Errorf("%s: duplicate member name", member)
	}
	return f, nil
}

func expandFixturePaths(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		info, err := os.Stat(a) //nolint:gosec // G703: operator-supplied CLI arg, not request-derived
		if err != nil {
			return nil, err
		}
		switch {
		case info.IsDir():
			fixDir := a
			if _, err := os.Stat(filepath.Join(a, "fixtures")); err == nil { //nolint:gosec // G703: operator-supplied CLI arg
				fixDir = filepath.Join(a, "fixtures")
			}
			entries, err := os.ReadDir(fixDir)
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
					out = append(out, filepath.Join(fixDir, e.Name()))
				}
			}
		default:
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out, nil
}

func relPath(p string) string {
	if wd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(wd, p); err == nil {
			return rel
		}
	}
	return p
}
