package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// revocationFixture decodes a §8.1 revocationList fixture holding the spec
// example entry. logIndex is the raw JSON for transparencyLogIndex; an empty
// string leaves the member out of the entry.
func revocationFixture(t *testing.T, logIndex string) fixture {
	t.Helper()
	member := ""
	if logIndex != "" {
		member = `"transparencyLogIndex": ` + logIndex + `,`
	}
	doc := `{
		"fixtureType": "revocationList",
		"revocationList": {
			"revocations": [{
				"agentDid": "did:opena2a:mcp_server:compromised-package",
				"revokedAt": "2026-03-22T15:00:00Z",
				"reason": "Supply chain compromise detected",
				` + member + `
				"revokedByKeyId": "did:opena2a:authority:opena2a.org#key-v3"
			}],
			"nextSince": "2026-03-22T15:00:00Z"
		}
	}`
	var f fixture
	if err := json.Unmarshal([]byte(doc), &f); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return f
}

// TestRevocationTransparencyLogIndexOptional uses the same cases as
// ../python/test_verify.py: an absent or null transparencyLogIndex does not
// reject the entry or the response, and a present index must be >= 0.
func TestRevocationTransparencyLogIndexOptional(t *testing.T) {
	cases := []struct {
		name       string
		logIndex   string
		wantAccept bool
	}{
		{"absent", "", true},
		{"null", "null", true},
		{"zero", "0", true},
		{"spec example", "1847300", true},
		{"negative", "-1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := verify(revocationFixture(t, tc.logIndex))
			if got.Accepted != tc.wantAccept {
				t.Fatalf("got %s, want accepted=%t", got, tc.wantAccept)
			}
			if !tc.wantAccept && (got.RejectCategory != "PARSE_ERROR" || !strings.Contains(got.Reason, "transparencyLogIndex")) {
				t.Fatalf("got %s, want PARSE_ERROR naming transparencyLogIndex", got)
			}
		})
	}
}

// setMember returns doc with the value at path (object keys and array
// indexes, in order) replaced by the raw JSON literal.
func setMember(t *testing.T, doc json.RawMessage, path []string, literal string) json.RawMessage {
	t.Helper()
	if len(path) == 0 {
		return json.RawMessage(literal)
	}
	if idx, err := strconv.Atoi(path[0]); err == nil {
		var arr []json.RawMessage
		if err := json.Unmarshal(doc, &arr); err != nil {
			t.Fatalf("decode array before index %d: %v", idx, err)
		}
		arr[idx] = setMember(t, arr[idx], path[1:], literal)
		out, err := json.Marshal(arr)
		if err != nil {
			t.Fatalf("encode array: %v", err)
		}
		return out
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(doc, &obj); err != nil {
		t.Fatalf("decode object before member %q: %v", path[0], err)
	}
	obj[path[0]] = setMember(t, obj[path[0]], path[1:], literal)
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("encode object: %v", err)
	}
	return out
}

// committedFixture loads a fixture from ../../fixtures by file name.
func committedFixture(t *testing.T, name string) fixture {
	t.Helper()
	f, err := loadFixture(filepath.Join("..", "..", "fixtures", name))
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return f
}

// mutatedFixture re-encodes the committed fixture name, replaces the member
// at the dotted path (array steps as indexes) with the raw JSON literal and
// decodes the result the way loadFixture does.
func mutatedFixture(t *testing.T, name, path, literal string) fixture {
	t.Helper()
	doc, err := json.Marshal(committedFixture(t, name))
	if err != nil {
		t.Fatalf("encode %s: %v", name, err)
	}
	var f fixture
	if err := json.Unmarshal(setMember(t, doc, strings.Split(path, "."), literal), &f); err != nil {
		t.Fatalf("decode %s with %s = %s: %v", name, path, literal, err)
	}
	return f
}

// schemaTypeViolations lists one member of a committed ACCEPT fixture
// replaced by a value whose JSON type or range the vendored schema rejects.
// ../python/test_verify.py holds the same table.
var schemaTypeViolations = []struct {
	fixture string
	path    string
	literal string
}{
	{"revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", `"5"`},
	{"revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", `"1847300"`},
	{"revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", `" 42 "`},
	{"revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", `"1_000"`},
	{"revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", `true`},
	{"revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", `false`},
	{"revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", `1847300.0`},
	{"revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", `1847300.5`},
	{"revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", `1e3`},
	{"revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", `1e30`},
	{"revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", `9223372036854775808`},
	{"revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", strings.Repeat("9", 400)},
	{"revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", `-0.5`},
	{"revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", `-0.999`},
	{"revocation-list-valid.json", "revocationList.revocations.0.reason", `1`},
	{"revocation-list-valid.json", "revocationList.revocations.0.revokedByKeyId", `["#"]`},
	{"revocation-list-valid.json", "revocationList.revocations", `{}`},
	{"revocation-list-valid.json", "revocationList.nextSince", `20260322`},
	{"trust-proof-baseline.json", "trustProof.trustLevel", `"3"`},
	{"trust-proof-baseline.json", "trustProof.trustLevel", `3.7`},
	{"trust-proof-baseline.json", "trustProof.trustScore", `"0.825"`},
	{"trust-proof-baseline.json", "trustProof.transparencyLogIndex", `"7"`},
	{"trust-proof-baseline.json", "trustProof.transparencyLogIndex", `-0.5`},
	{"trust-proof-baseline.json", "trustProof.transparencyLogIndex", `-5`},
	{"trust-proof-baseline.json", "trustProof.signatures.0.value", `42`},
	{"transparency-inclusion-proof-valid.json", "inclusionProof.logIndex", `3.5`},
	{"transparency-inclusion-proof-valid.json", "inclusionProof.logIndex", `"3"`},
	{"transparency-inclusion-proof-valid.json", "inclusionProof.signedTreeHead.treeSize", `"8"`},
	{"transparency-inclusion-proof-valid.json", "inclusionProof.auditPath", `"SHA256:00"`},
	{"transparency-consistency-proof-valid.json", "consistencyProof.fromSize", `"4"`},
	{"transparency-log-sth.json", "signedTreeHead.treeSize", `"1847294"`},
	{"transparency-log-sth.json", "signedTreeHead.rootHash", `["SHA256:00"]`},
	{"discovery-valid.json", "discoveryResponse.conformanceLevel", `2.5`},
	{"discovery-valid.json", "discoveryResponse.conformanceLevel", `true`},
	{"discovery-valid.json", "discoveryResponse.version", `1.0`},
	{"discovery-valid.json", "discoveryResponse.endpoints", `["/api/v1/trust/proof"]`},
}

func shortLiteral(literal string) string {
	if len(literal) > 24 {
		return literal[:12] + "..."
	}
	return literal
}

// TestSchemaTypeViolationIsParseError: a member whose JSON type or range
// violates the vendored schema is REJECT[PARSE_ERROR] naming the member,
// the verdict the Python verifier returns for the same input, not a load
// error and not ACCEPT. The unmodified fixtures verify ACCEPT, so in each
// case the one changed member is the sole defect.
func TestSchemaTypeViolationIsParseError(t *testing.T) {
	seen := map[string]bool{}
	for _, tc := range schemaTypeViolations {
		if seen[tc.fixture] {
			continue
		}
		seen[tc.fixture] = true
		if got := verify(committedFixture(t, tc.fixture)); !got.Accepted {
			t.Fatalf("%s unmodified: got %s, want ACCEPT", tc.fixture, got)
		}
	}
	for _, tc := range schemaTypeViolations {
		t.Run(tc.path+"="+shortLiteral(tc.literal), func(t *testing.T) {
			got := verify(mutatedFixture(t, tc.fixture, tc.path, tc.literal))
			member := tc.path[strings.LastIndex(tc.path, ".")+1:]
			if got.Accepted || got.RejectCategory != "PARSE_ERROR" || !strings.Contains(got.Reason, member) {
				t.Fatalf("got %s, want PARSE_ERROR naming %s", got, member)
			}
		})
	}
}

// nullViolations lists one member of a committed ACCEPT fixture set to JSON
// null where the vendored schema gives it a type: each member kind (string,
// integer, number, array, array element, object, object value) on each
// payload type. ../python/test_verify.py holds the same table.
var nullViolations = []struct {
	fixture string
	path    string
}{
	{"revocation-list-valid.json", "revocationList.revocations"},
	{"revocation-list-valid.json", "revocationList.revocations.0"},
	{"revocation-list-valid.json", "revocationList.revocations.0.agentDid"},
	{"revocation-list-valid.json", "revocationList.revocations.0.reason"},
	{"revocation-list-valid.json", "revocationList.revocations.0.revokedByKeyId"},
	{"revocation-list-valid.json", "revocationList.nextSince"},
	{"trust-proof-baseline.json", "trustProof.did"},
	{"trust-proof-baseline.json", "trustProof.trustLevel"},
	{"trust-proof-baseline.json", "trustProof.trustScore"},
	{"trust-proof-baseline.json", "trustProof.signatures"},
	{"trust-proof-baseline.json", "trustProof.signatures.0.value"},
	{"transparency-inclusion-proof-valid.json", "inclusionProof.logIndex"},
	{"transparency-inclusion-proof-valid.json", "inclusionProof.auditPath"},
	{"transparency-inclusion-proof-valid.json", "inclusionProof.auditPath.0"},
	{"transparency-inclusion-proof-valid.json", "inclusionProof.signedTreeHead.treeSize"},
	{"transparency-consistency-proof-valid.json", "consistencyProof.fromSize"},
	{"transparency-consistency-proof-valid.json", "consistencyProof.consistencyPath"},
	{"transparency-consistency-proof-valid.json", "consistencyProof.toSignedTreeHead.rootHash"},
	{"transparency-log-sth.json", "signedTreeHead.treeSize"},
	{"transparency-log-sth.json", "signedTreeHead.timestamp"},
	{"discovery-valid.json", "discoveryResponse.conformanceLevel"},
	{"discovery-valid.json", "discoveryResponse.authorityDid"},
	{"discovery-valid.json", "discoveryResponse.endpoints"},
	{"discovery-valid.json", "discoveryResponse.endpoints.trustProof"},
	{"discovery-valid.json", "discoveryResponse.publicKeys.0.status"},
	{"discovery-valid.json", "discoveryResponse.supportedMethods"},
}

// memberLabel writes a dotted fixture path the way both verifiers name the
// member in a reason, with array steps as [index].
func memberLabel(path string) string {
	var b strings.Builder
	for _, step := range strings.Split(path, ".") {
		switch _, err := strconv.Atoi(step); {
		case err == nil:
			b.WriteString("[" + step + "]")
		case b.Len() > 0:
			b.WriteString("." + step)
		default:
			b.WriteString(step)
		}
	}
	return b.String()
}

// TestNullMemberIsParseError: JSON null is a value of no schema type, so a
// null member is REJECT[PARSE_ERROR] naming the member, the verdict the
// Python verifier returns for the same input, and not the zero value
// encoding/json decodes it to. revocations null is not an empty revocation
// list, and logIndex null is not leaf 0. The unmodified fixtures verify
// ACCEPT (TestSchemaTypeViolationIsParseError checks each one).
func TestNullMemberIsParseError(t *testing.T) {
	for _, tc := range nullViolations {
		t.Run(tc.path, func(t *testing.T) {
			got := verify(mutatedFixture(t, tc.fixture, tc.path, `null`))
			want := memberLabel(tc.path) + ": JSON null does not fit the "
			if got.Accepted || got.RejectCategory != "PARSE_ERROR" || !strings.HasPrefix(got.Reason, want) {
				t.Fatalf("got %s, want PARSE_ERROR beginning %q", got, want)
			}
		})
	}
}

// TestNullOptionalOrEmbeddedMember: the members that take null take it as
// absent. An optional transparencyLogIndex is then not checked (the §8.1
// entry's index is in TestRevocationTransparencyLogIndexOptional) and an
// embedded tree head is reported missing.
func TestNullOptionalOrEmbeddedMember(t *testing.T) {
	cases := []struct {
		fixture    string
		path       string
		wantAccept bool
		wantReason string
	}{
		{"trust-proof-baseline.json", "trustProof.transparencyLogIndex", true, ""},
		{"transparency-inclusion-proof-valid.json", "inclusionProof.signedTreeHead", false, "signedTreeHead missing"},
		{"transparency-consistency-proof-valid.json", "consistencyProof.fromSignedTreeHead", false, "fromSignedTreeHead/toSignedTreeHead missing"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			got := verify(mutatedFixture(t, tc.fixture, tc.path, `null`))
			if got.Accepted != tc.wantAccept {
				t.Fatalf("got %s, want accepted=%t", got, tc.wantAccept)
			}
			if !tc.wantAccept && (got.RejectCategory != "PARSE_ERROR" || !strings.Contains(got.Reason, tc.wantReason)) {
				t.Fatalf("got %s, want PARSE_ERROR with %q", got, tc.wantReason)
			}
		})
	}
}

// renameMember returns doc with the object member at path (object keys and
// array indexes, in order) renamed to rename with its value kept, or left
// out when rename is "".
func renameMember(t *testing.T, doc json.RawMessage, path []string, rename string) json.RawMessage {
	t.Helper()
	if idx, err := strconv.Atoi(path[0]); err == nil {
		var arr []json.RawMessage
		if err := json.Unmarshal(doc, &arr); err != nil {
			t.Fatalf("decode array before index %d: %v", idx, err)
		}
		arr[idx] = renameMember(t, arr[idx], path[1:], rename)
		out, err := json.Marshal(arr)
		if err != nil {
			t.Fatalf("encode array: %v", err)
		}
		return out
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(doc, &obj); err != nil {
		t.Fatalf("decode object before member %q: %v", path[0], err)
	}
	if len(path) > 1 {
		obj[path[0]] = renameMember(t, obj[path[0]], path[1:], rename)
	} else {
		value, ok := obj[path[0]]
		if !ok {
			t.Fatalf("no member %q to rename", path[0])
		}
		delete(obj, path[0])
		if rename != "" {
			obj[rename] = value
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("encode object: %v", err)
	}
	return out
}

// renamedFixture loads the committed fixture name from ../../fixtures the
// way loadFixture does, with the member at the dotted path (array steps as
// indexes) renamed to rename, or left out when rename is "".
func renamedFixture(t *testing.T, name, path, rename string) fixture {
	t.Helper()
	doc, err := fs.ReadFile(os.DirFS(filepath.Join("..", "..", "fixtures")), name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	f, err := parseFixture(renameMember(t, doc, strings.Split(path, "."), rename))
	if err != nil {
		t.Fatalf("load %s with %s renamed to %q: %v", name, path, rename, err)
	}
	return f
}

// caseVariantMembers lists one member of a committed ACCEPT fixture renamed
// to a name that differs from the schema's only in letter case, with the
// verdict both verifiers return: ACCEPT or the REJECT category. A key of the
// free-form endpoints object is data, not a schema member name, and is kept
// as written. ../python/test_verify.py holds the same table.
var caseVariantMembers = []struct {
	fixture string
	path    string
	rename  string
	want    string
}{
	{"transparency-log-sth.json", "signedTreeHead.treeSize", "TreeSize", "STH_INVALID"},
	{"transparency-log-sth.json", "signedTreeHead.treeSize", "treesize", "STH_INVALID"},
	{"transparency-log-sth.json", "signedTreeHead.treeSize", "tree\U0000017fize", "STH_INVALID"},
	{"transparency-log-sth.json", "signedTreeHead", "SignedTreeHead", "PARSE_ERROR"},
	{"transparency-log-sth.json", "fixtureType", "FixtureType", "PARSE_ERROR"},
	{"trust-proof-baseline.json", "trustProof.issuerDid", "issuerDID", "UNTRUSTED_ISSUER"},
	{"trust-proof-baseline.json", "trustProof.signatures.0.value", "Value", "SIGNATURE_INVALID"},
	{"transparency-inclusion-proof-valid.json", "inclusionProof.signedTreeHead.treeSize", "TreeSize", "STH_INVALID"},
	{"transparency-consistency-proof-valid.json", "consistencyProof.toSize", "ToSize", "PARSE_ERROR"},
	{"revocation-list-valid.json", "revocationList.revocations.0.revokedByKeyId", "revokedByKeyID", "PARSE_ERROR"},
	{"discovery-valid.json", "discoveryResponse.authorityDid", "AuthorityDid", "DISCOVERY_INVALID"},
	{"discovery-valid.json", "discoveryResponse.endpoints.trustProof", "TrustProof", "ACCEPT"},
}

// TestCaseVariantMemberIsAbsent: JSON member names are case-sensitive and
// the Python verifier reads each member by its exact name, so a member
// renamed to another letter case verifies the same as the fixture with that
// member left out. encoding/json alone matches TreeSize, treesize and
// "tree\U0000017fize" (U+017F folds to S) to treeSize and the fixture
// verifies ACCEPT. The unmodified fixtures verify ACCEPT
// (TestSchemaTypeViolationIsParseError checks each one).
func TestCaseVariantMemberIsAbsent(t *testing.T) {
	for _, tc := range caseVariantMembers {
		t.Run(tc.path+"="+tc.rename, func(t *testing.T) {
			got := verify(renamedFixture(t, tc.fixture, tc.path, tc.rename))
			if absent := verify(renamedFixture(t, tc.fixture, tc.path, "")); got.String() != absent.String() {
				t.Fatalf("renamed: %s, left out: %s", got, absent)
			}
			verdict := got.RejectCategory
			if got.Accepted {
				verdict = "ACCEPT"
			}
			if verdict != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// verifierStateMembers leaves one member of a committed fixture's
// verifierState, the verifier configuration, out (literal "") or replaces it
// with the raw JSON literal, with the outcome both verifiers return: ACCEPT,
// the REJECT category, or "load error". ../python/test_verify.py holds the
// same table.
var verifierStateMembers = []struct {
	fixture string
	path    string
	literal string
	want    string
}{
	{"transparency-log-sth.json", "verifierState", "", "SIGNATURE_INVALID"},
	{"transparency-log-sth.json", "verifierState", "null", "SIGNATURE_INVALID"},
	{"transparency-log-sth.json", "verifierState.publicKeys", "", "SIGNATURE_INVALID"},
	{"transparency-log-sth.json", "verifierState.publicKeys", "null", "SIGNATURE_INVALID"},
	{"transparency-log-sth.json", "verifierState.publicKeys.0.publicKeyHex", "", "SIGNATURE_INVALID"},
	{"transparency-log-sth.json", "verifierState.publicKeys.0.publicKeyHex", "null", "SIGNATURE_INVALID"},
	{"transparency-log-sth.json", "verifierState.publicKeys.0.algorithm", "", "SIGNATURE_INVALID"},
	{"trust-proof-baseline.json", "verifierState", "", "VERIFIER_CONFIG_ERROR"},
	{"trust-proof-baseline.json", "verifierState.clockRfc3339", "", "VERIFIER_CONFIG_ERROR"},
	{"trust-proof-baseline.json", "verifierState.clockRfc3339", "null", "VERIFIER_CONFIG_ERROR"},
	{"trust-proof-baseline.json", "verifierState.trustedIssuers", "", "UNTRUSTED_ISSUER"},
	{"discovery-valid.json", "verifierState", "", "UNTRUSTED_ISSUER"},
	{"discovery-valid.json", "verifierState.trustedIssuers.0", "null", "UNTRUSTED_ISSUER"},
	{"transparency-inclusion-proof-valid.json", "verifierState", "", "SIGNATURE_INVALID"},
	{"transparency-consistency-proof-valid.json", "verifierState", "", "SIGNATURE_INVALID"},
	{"transparency-log-sth.json", "verifierState", `"x"`, "load error"},
	{"transparency-log-sth.json", "verifierState.publicKeys", `{}`, "load error"},
	{"transparency-log-sth.json", "verifierState.publicKeys.0.publicKeyHex", `5`, "load error"},
	{"trust-proof-baseline.json", "verifierState.clockRfc3339", `5`, "load error"},
}

// TestVerifierStateMember: parseFixture decodes verifierState with
// encoding/json, so an absent or null member is its zero value, which the
// verification steps then judge (no clock, no trusted issuer, no public
// key), and a member of the wrong JSON type is a load error, the outcome the
// Python verifier returns for the same input. The unmodified fixtures verify
// ACCEPT (TestSchemaTypeViolationIsParseError checks each one).
func TestVerifierStateMember(t *testing.T) {
	for _, tc := range verifierStateMembers {
		t.Run(tc.fixture+":"+tc.path+"="+tc.literal, func(t *testing.T) {
			doc, err := os.ReadFile(filepath.Join("..", "..", "fixtures", tc.fixture))
			if err != nil {
				t.Fatal(err)
			}
			path := strings.Split(tc.path, ".")
			if tc.literal == "" {
				doc = renameMember(t, doc, path, "")
			} else {
				doc = setMember(t, doc, path, tc.literal)
			}
			f, err := parseFixture(doc)
			if err != nil {
				if tc.want != "load error" {
					t.Fatalf("load error %v, want %s", err, tc.want)
				}
				return
			}
			got := verify(f)
			verdict := got.RejectCategory
			if got.Accepted {
				verdict = "ACCEPT"
			}
			if verdict != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// repeatedNames writes a member name twice into one JSON object of a
// committed ACCEPT fixture: old occurs once in the file and new replaces it.
// Inside a payload member the repeat is REJECT[PARSE_ERROR] naming the first
// repeated member in document order, whatever the values are; anywhere else
// in the document it is a load error. ../python/test_verify.py holds the
// same table.
var repeatedNames = []struct {
	fixture, old, new, member string
	loadError                 bool
}{
	{"transparency-log-sth.json", `"treeSize": 1847294,`, `"treeSize": "x", "treeSize": 1847294,`, "signedTreeHead.treeSize", false},
	{"transparency-log-sth.json", `"treeSize": 1847294,`, `"treeSize": 1847294, "treeSize": "x",`, "signedTreeHead.treeSize", false},
	{"transparency-log-sth.json", `"treeSize": 1847294,`, `"treeSize": 0, "treeSize": 1847294,`, "signedTreeHead.treeSize", false},
	{"transparency-log-sth.json", `"treeSize": 1847294,`, `"treeSize": 1847294, "treeSize": 1847294,`, "signedTreeHead.treeSize", false},
	{"transparency-log-sth.json", `"treeSize": 1847294,`, `"note": {"a": 1, "a": 2}, "treeSize": 1847294,`, "signedTreeHead.note.a", false},
	{"transparency-log-sth.json", `"treeSize": 1847294,`, `"note": {"b": 1, "b": 2}, "note": 3, "treeSize": 1847294,`, "signedTreeHead.note.b", false},
	{"transparency-log-sth.json", `"treeSize": 1847294,`, `"note": 3, "note": {"b": 1, "b": 2}, "treeSize": 1847294,`, "signedTreeHead.note", false},
	{"transparency-log-sth.json", `"treeSize": 1847294,`, `"note": 1e400, "treeSize": 1847294, "treeSize": 1847294,`, "signedTreeHead.treeSize", false},
	{"trust-proof-baseline.json", `"trustLevel": 3,`, `"trustLevel": 4, "trustLevel": 3,`, "trustProof.trustLevel", false},
	{"revocation-list-valid.json", `"reason": "Supply chain compromise detected",`, `"reason": "", "reason": "Supply chain compromise detected",`, "revocationList.revocations[0].reason", false},
	{"transparency-inclusion-proof-valid.json", `"treeSize": 8,`, `"treeSize": 8, "treeSize": 8,`, "inclusionProof.signedTreeHead.treeSize", false},
	{"transparency-consistency-proof-valid.json", `"fromSize": 4,`, `"fromSize": 4, "fromSize": 4,`, "consistencyProof.fromSize", false},
	{"discovery-valid.json", `"trustProof": "/api/v1/trust/proof",`, `"trustProof": "/x", "trustProof": "/api/v1/trust/proof",`, "discoveryResponse.endpoints.trustProof", false},
	{"transparency-log-sth.json", `"expected": {`, `"verifierState": {"clockRfc3339": "2026-05-24T00:00:00Z"}, "expected": {`, "verifierState", true},
	{"transparency-log-sth.json", `"clockRfc3339": "2026-05-24T00:00:00Z",`, `"clockRfc3339": "2026-05-24T00:00:00Z", "clockRfc3339": "2026-05-24T00:00:00Z",`, "verifierState.clockRfc3339", true},
	{"transparency-log-sth.json", `"verifyResult": "ACCEPT"`, `"verifyResult": "REJECT", "verifyResult": "ACCEPT"`, "expected.verifyResult", true},
	{"transparency-log-sth.json", `"signedTreeHead": {`, `"signedTreeHead": {}, "signedTreeHead": {`, "signedTreeHead", true},
}

// TestRepeatedMemberName: encoding/json and Python's json.loads read a
// repeated member name differently, so both verifiers refuse it with the
// same text: REJECT[PARSE_ERROR] inside a payload member and a load error
// elsewhere. The unmodified fixtures verify ACCEPT
// (TestSchemaTypeViolationIsParseError checks each one).
func TestRepeatedMemberName(t *testing.T) {
	for _, tc := range repeatedNames {
		t.Run(tc.member, func(t *testing.T) {
			doc, err := os.ReadFile(filepath.Join("..", "..", "fixtures", tc.fixture))
			if err != nil {
				t.Fatal(err)
			}
			if n := strings.Count(string(doc), tc.old); n != 1 {
				t.Fatalf("%s holds %q %d times, want once", tc.fixture, tc.old, n)
			}
			f, err := parseFixture([]byte(strings.Replace(string(doc), tc.old, tc.new, 1)))
			want := tc.member + ": duplicate member name"
			if tc.loadError {
				if err == nil || err.Error() != want {
					t.Fatalf("load error %v, want %q", err, want)
				}
				return
			}
			if err != nil {
				t.Fatalf("load error %v, want REJECT[PARSE_ERROR: %s]", err, want)
			}
			if got := verify(f); got.Accepted || got.RejectCategory != "PARSE_ERROR" || got.Reason != want {
				t.Fatalf("got %s, want REJECT[PARSE_ERROR: %s]", got, want)
			}
		})
	}
}

// TestExactMembers: a member whose name is not exactly a field's JSON name
// is left out, the members kept stay in document order with repeated names
// included, a map key is kept as written, a payload member of the fixture
// document stays raw for decodePayload, and a value that is not the JSON
// type the target needs is returned unchanged.
func TestExactMembers(t *testing.T) {
	cases := []struct {
		target any
		raw    string
		want   string
	}{
		{signedTreeHead{}, `{"timestamp":"t","TreeSize":2,"treeSize":1,"extra":0,"treeSize":3}`, `{"timestamp":"t","treeSize":1,"treeSize":3}`},
		{discoveryResponse{}, `{"Endpoints":{},"endpoints":{"TrustProof":"/p"}}`, `{"endpoints":{"TrustProof":"/p"}}`},
		{revocationList{}, `{"revocations":[{"Reason":"r","reason":"s"},7,null]}`, `{"revocations":[{"reason":"s"},7,null]}`},
		{revocationList{}, `{"revocations":null}`, `{"revocations":null}`},
		{fixture{}, `{"FixtureType":"sth","expected":{"VerifyResult":"ACCEPT","verifyResult":"REJECT"},"VerifierState":{},"signedTreeHead":{"TreeSize":1}}`, `{"expected":{"verifyResult":"REJECT"},"signedTreeHead":{"TreeSize":1}}`},
		{signedTreeHead{}, `null`, `null`},
		{signedTreeHead{}, `"x"`, `"x"`},
	}
	for _, tc := range cases {
		if got := string(exactMembers(json.RawMessage(tc.raw), reflect.TypeOf(tc.target))); got != tc.want {
			t.Errorf("exactMembers(%s) = %s, want %s", tc.raw, got, tc.want)
		}
	}
}

// timestampMembers are the trust-proof timestamps, as dotted paths in a
// trustProof fixture.
var timestampMembers = []string{"trustProof.issuedAt", "trustProof.expiresAt", "verifierState.clockRfc3339"}

// timestampRangeEdges lists timestamps at the edges of the years 1 to 9999,
// each set in turn as the issuedAt, expiresAt and verifier clockRfc3339 of
// trust-proof-baseline.json, with the verdict both verifiers return for
// each: ACCEPT or the REJECT category. A UTC equivalent that differs from
// the value is noted beside it. ../python/test_verify.py holds the same
// table.
var timestampRangeEdges = []struct {
	value                      string
	issuedAt, expiresAt, clock string
}{
	{"0001-01-01T00:00:00+01:00", "PARSE_ERROR", "PARSE_ERROR", "VERIFIER_CONFIG_ERROR"}, // 0000-12-31T23:00:00Z
	{"9999-12-31T23:59:59-01:00", "PARSE_ERROR", "PARSE_ERROR", "VERIFIER_CONFIG_ERROR"}, // 10000-01-01T00:59:59Z
	{"0000-06-15T00:00:00Z", "PARSE_ERROR", "PARSE_ERROR", "VERIFIER_CONFIG_ERROR"},
	{"0000-12-31T23:30:00-01:00", "PARSE_ERROR", "PARSE_ERROR", "VERIFIER_CONFIG_ERROR"}, // 0001-01-01T00:30:00Z
	{"0001-01-01T00:00:00Z", "SEMANTIC_INVALID", "EXPIRED", "ACCEPT"},
	{"0001-01-01T00:59:59+00:59", "SEMANTIC_INVALID", "EXPIRED", "ACCEPT"}, // 0001-01-01T00:00:59Z
	{"9999-12-31T23:59:59Z", "SEMANTIC_INVALID", "SEMANTIC_INVALID", "EXPIRED"},
	{"9999-12-31T23:00:00-00:59", "SEMANTIC_INVALID", "SEMANTIC_INVALID", "EXPIRED"}, // 9999-12-31T23:59:00Z
}

// outOfRangeUTC are the timestamps of timestampRangeEdges that are written
// inside the years 1 to 9999 and whose UTC equivalent falls outside them.
// ../python/test_verify.py holds them as OUT_OF_RANGE_TIMES.
var outOfRangeUTC = []string{"0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"}

// TestTimestampRangeEdges: a trust-proof timestamp whose date as written or
// whose UTC equivalent falls outside the years 1 to 9999 is refused at the
// step that reads it, before a step compares it. In
// trust-proof-baseline.json that is PARSE_ERROR as issuedAt or expiresAt and
// VERIFIER_CONFIG_ERROR as the verifier's clock, with a reason naming the
// member, the verdicts the Python verifier, whose datetime holds no other
// years, returns for the same input. time.Parse alone reads a date written
// in year 0000 and puts the UTC equivalent of an offset time in year 0 or
// 10000. A timestamp inside the years, at either end, goes on to the
// verification steps.
func TestTimestampRangeEdges(t *testing.T) {
	for _, tc := range timestampRangeEdges {
		for i, want := range []string{tc.issuedAt, tc.expiresAt, tc.clock} {
			path := timestampMembers[i]
			t.Run(path+"="+tc.value, func(t *testing.T) {
				got := verify(mutatedFixture(t, "trust-proof-baseline.json", path, strconv.Quote(tc.value)))
				verdict := got.RejectCategory
				if got.Accepted {
					verdict = "ACCEPT"
				}
				if verdict != want {
					t.Fatalf("got %s, want %s", got, want)
				}
				prefix := "bad " + path[strings.LastIndex(path, ".")+1:] + ": "
				if (want == "PARSE_ERROR" || want == "VERIFIER_CONFIG_ERROR") && !strings.HasPrefix(got.Reason, prefix) {
					t.Fatalf("got %s, want a reason beginning %q", got, prefix)
				}
			})
		}
	}
}

// TestOutOfRangeUTCReason: both verifiers give the same reason for a
// timestamp written inside the years 1 to 9999 whose UTC equivalent falls
// outside them.
func TestOutOfRangeUTCReason(t *testing.T) {
	for _, path := range timestampMembers {
		for _, value := range outOfRangeUTC {
			t.Run(path+"="+value, func(t *testing.T) {
				got := verify(mutatedFixture(t, "trust-proof-baseline.json", path, strconv.Quote(value)))
				want := "bad " + path[strings.LastIndex(path, ".")+1:] + ": " + value + " falls outside the years 1 to 9999 in UTC"
				if got.Reason != want {
					t.Fatalf("got %s, want reason %q", got, want)
				}
			})
		}
	}
}

// outcome is the verdict of r as the tables below write it: ACCEPT or the
// REJECT category.
func outcome(r result) string {
	if r.Accepted {
		return "ACCEPT"
	}
	return r.RejectCategory
}

// jsonString is s written as a JSON string literal.
func jsonString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// memberValue returns the string member at the dotted path (array steps as
// indexes) of the committed fixture name.
func memberValue(t *testing.T, name, path string) string {
	t.Helper()
	doc, err := fs.ReadFile(os.DirFS(filepath.Join("..", "..", "fixtures")), name)
	if err != nil {
		t.Fatal(err)
	}
	var cur any
	if err := json.Unmarshal(doc, &cur); err != nil {
		t.Fatal(err)
	}
	for _, step := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]any:
			cur = node[step]
		case []any:
			i, err := strconv.Atoi(step)
			if err != nil || i < 0 || i >= len(node) {
				t.Fatalf("%s: %s has no element %s", name, path, step)
			}
			cur = node[i]
		default:
			t.Fatalf("%s: %s has no member %s", name, path, step)
		}
	}
	s, ok := cur.(string)
	if !ok {
		t.Fatalf("%s: %s is not a string", name, path)
	}
	return s
}

// timestampGrammarMembers lists timestamp members of committed ACCEPT
// fixtures, each with the REJECT category both verifiers return when it
// holds a string that is not an RFC 3339 date-time (the category of the
// step that reads it), and the verdict ACCEPT where no step signs the
// member or compares it with another time, so any RFC 3339 date-time leaves
// the fixture valid ("" where the verdict depends on the time).
// ../python/test_verify.py holds the same table.
var timestampGrammarMembers = []struct {
	fixture, path, refused, read string
}{
	{"trust-proof-baseline.json", "verifierState.clockRfc3339", "VERIFIER_CONFIG_ERROR", ""},
	{"trust-proof-baseline.json", "trustProof.issuedAt", "PARSE_ERROR", ""},
	{"trust-proof-baseline.json", "trustProof.expiresAt", "PARSE_ERROR", ""},
	{"revocation-list-valid.json", "revocationList.nextSince", "PARSE_ERROR", "ACCEPT"},
	{"revocation-list-valid.json", "revocationList.revocations.0.revokedAt", "PARSE_ERROR", "ACCEPT"},
	{"transparency-log-sth.json", "signedTreeHead.timestamp", "STH_INVALID", "ACCEPT"},
	{"transparency-inclusion-proof-valid.json", "inclusionProof.signedTreeHead.timestamp", "STH_INVALID", "ACCEPT"},
	{"transparency-consistency-proof-valid.json", "consistencyProof.toSignedTreeHead.timestamp", "STH_INVALID", "ACCEPT"},
}

// notRFC3339 lists strings that are not RFC 3339 date-times, refused in
// every member of timestampGrammarMembers, with the parser that reads the
// string on its own: Python's fromisoformat (after "Z" is replaced by
// "+00:00"), time.Parse with the time.RFC3339 layout, both or neither.
// ../python/test_verify.py holds the same list.
var notRFC3339 = []string{
	"2026-05-24 00:00:00Z",          // fromisoformat
	"2026-05-24t00:00:00Z",          // fromisoformat
	"2026-05-24T00:00:00",           // fromisoformat, with no zone
	"2026-05-24T00:00:00+0000",      // fromisoformat
	"20260524T000000Z",              // fromisoformat
	"2026-05-24T00:00Z",             // fromisoformat
	"2026-05-24T00Z",                // fromisoformat
	"2026-W21-7T00:00:00Z",          // fromisoformat
	"2026-05-24T00:00:00+01",        // fromisoformat
	"2026-05-24T00:00:00+00",        // fromisoformat
	"2026-05-24T00:00:00+00:00:00",  // fromisoformat
	"2026-05-24T00:00:00.Z",         // fromisoformat
	"2026-05-24T00:00:00 Z",         // fromisoformat
	"2026-05-24T24:00:00Z",          // fromisoformat from Python 3.14, as the next midnight
	"2026-05-24T0:00:00Z",           // time.Parse
	"2026-05-24T00:00:00+24:00",     // time.Parse
	"2026-05-24T00:00:00-24:00",     // time.Parse
	"0000-01-01T00:00:00Z",          // time.Parse
	"2026-05-24T00:00:00,5Z",        // both
	"2026-05-24T00:00:00+00:60",     // both
	"2026-05-24T00:00:00z",          // neither
	"2026-05-24T23:59:60Z",          // neither
	"2026-02-29T00:00:00Z",          // neither
	"2026-05-24T00:00:00Z\n",        // neither
	"\U0000ff12026-05-24T00:00:00Z", // neither: U+FF12 FULLWIDTH DIGIT TWO, then 026
	"",                              // neither
}

// rfc3339DateTimes lists RFC 3339 date-times both verifiers read.
// ../python/test_verify.py holds the same list.
var rfc3339DateTimes = []string{
	"2026-05-24T00:00:00Z",
	"2026-05-24T00:00:00.5Z",
	"2026-05-24T00:00:00.123456789012Z",
	"2026-05-23T20:00:00-04:00",
	"2026-05-24T05:30:00+05:30",
	"2026-05-24T00:00:00-00:00",
	"2026-05-24T00:00:00+23:59",
	"2024-02-29T00:00:00Z",
	"0001-01-01T00:00:00Z",
	"9999-12-31T23:59:59Z",
}

// sameTimeTimestamps lists trust-proof timestamps of
// trust-proof-baseline.json written another way for the same time, which
// leaves the signed form and the verdict ACCEPT. ../python/test_verify.py
// holds the same table.
var sameTimeTimestamps = []struct{ path, value string }{
	{"trustProof.issuedAt", "2026-05-23T08:00:00-04:00"},
	{"trustProof.expiresAt", "2026-05-24T08:00:00+02:00"},
	{"trustProof.expiresAt", "2026-05-24T06:00:00.000Z"},
	{"verifierState.clockRfc3339", "2026-05-23T20:00:00-04:00"},
}

// TestNotRFC3339IsRefused: each timestamp, the verifier's clockRfc3339
// included, is read only as an RFC 3339 date-time with an upper-case T and
// Z, the strings the Python verifier's _parse_rfc3339_strict reads, and any
// other string is refused with the category of the step that reads it, the
// verdict the Python verifier returns for the same input. The unmodified
// fixtures verify ACCEPT (TestSchemaTypeViolationIsParseError checks each
// one).
func TestNotRFC3339IsRefused(t *testing.T) {
	for _, tc := range timestampGrammarMembers {
		for _, value := range notRFC3339 {
			t.Run(tc.path+"="+strconv.Quote(value), func(t *testing.T) {
				got := verify(mutatedFixture(t, tc.fixture, tc.path, jsonString(t, value)))
				if outcome(got) != tc.refused {
					t.Fatalf("got %s, want %s", got, tc.refused)
				}
			})
		}
	}
}

// TestRFC3339IsRead: an RFC 3339 date-time in a member no step signs or
// compares leaves the fixture ACCEPT.
func TestRFC3339IsRead(t *testing.T) {
	for _, tc := range timestampGrammarMembers {
		if tc.read == "" {
			continue
		}
		for _, value := range rfc3339DateTimes {
			t.Run(tc.path+"="+value, func(t *testing.T) {
				got := verify(mutatedFixture(t, tc.fixture, tc.path, jsonString(t, value)))
				if outcome(got) != tc.read {
					t.Fatalf("got %s, want %s", got, tc.read)
				}
			})
		}
	}
}

// TestSameTimeWrittenAnotherWay: a trust proof's timestamps and the
// verifier's clock written with an offset or a fraction for the same time
// verify ACCEPT.
func TestSameTimeWrittenAnotherWay(t *testing.T) {
	for _, tc := range sameTimeTimestamps {
		t.Run(tc.path+"="+tc.value, func(t *testing.T) {
			got := verify(mutatedFixture(t, "trust-proof-baseline.json", tc.path, jsonString(t, tc.value)))
			if !got.Accepted {
				t.Fatalf("got %s, want ACCEPT", got)
			}
		})
	}
}

// subMicrosecondTimestamps lists the issuedAt, expiresAt and verifier
// clockRfc3339 of trust-proof-baseline.json ("" keeps the fixture's value)
// written with a fraction of a second of more than six digits, or a
// microsecond past the edge of a comparison, with the verdict both
// verifiers return. The proof expires at 2026-05-24T06:00:00Z, 18 hours
// after its issuedAt, and the clock is 2026-05-24T00:00:00Z.
// ../python/test_verify.py holds the same table.
var subMicrosecondTimestamps = []struct {
	issuedAt, expiresAt, clock, want string
}{
	{"", "", "2026-05-24T06:00:00.0000001Z", "ACCEPT"}, // the clock reads as the expiry time
	{"", "", "2026-05-24T06:00:00.0000009Z", "ACCEPT"}, // dropped, not rounded up
	{"", "", "2026-05-24T06:00:00.000000999999Z", "ACCEPT"},
	{"", "", "2026-05-24T07:00:00.0000001+01:00", "ACCEPT"},
	{"", "", "2026-05-24T06:00:00.000001Z", "EXPIRED"}, // a microsecond after the expiry time
	{"", "2026-05-24T06:00:00.0000001Z", "2026-05-24T06:00:00.0000002Z", "ACCEPT"},
	{"", "2026-05-24T12:00:00.0000001Z", "", "SIGNATURE_INVALID"},                    // a 24-hour window; the signed form then holds 12:00:00
	{"", "2026-05-24T12:00:00.000001Z", "", "SEMANTIC_INVALID"},                      // a window a microsecond over 24 hours
	{"2026-05-24T06:00:00Z", "2026-05-24T06:00:00.0000001Z", "", "SEMANTIC_INVALID"}, // expiresAt reads as issuedAt
	{"2026-05-24T06:00:00Z", "2026-05-24T06:00:00.000001Z", "", "SIGNATURE_INVALID"}, // issued a microsecond before expiry; the signed form then holds the new issuedAt
}

// baselineWithTimestamps returns trust-proof-baseline.json with its
// issuedAt, expiresAt and verifier clockRfc3339 set to values, in that
// order ("" keeps the fixture's value).
func baselineWithTimestamps(t *testing.T, values []string) fixture {
	t.Helper()
	doc, err := json.Marshal(committedFixture(t, "trust-proof-baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	for i, value := range values {
		if value != "" {
			doc = setMember(t, doc, strings.Split(timestampMembers[i], "."), jsonString(t, value))
		}
	}
	var f fixture
	if err := json.Unmarshal(doc, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestSubMicrosecondFraction: both verifiers read a timestamp to the
// microsecond, dropping any digit of its fraction after the sixth, so the
// expiry check, the issuedAt-before-expiresAt check and the 24-hour window
// compare the same times in each and return the same verdict.
// time.Parse alone keeps nine digits, and Python's datetime holds six.
func TestSubMicrosecondFraction(t *testing.T) {
	for _, tc := range subMicrosecondTimestamps {
		values := []string{tc.issuedAt, tc.expiresAt, tc.clock}
		t.Run(strings.Join(values, ","), func(t *testing.T) {
			if got := verify(baselineWithTimestamps(t, values)); outcome(got) != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// expiredReasons lists the expiresAt and verifier clockRfc3339 of
// trust-proof-baseline.json ("" keeps the fixture's value) for which both
// verifiers return EXPIRED, with the reason both give: each time in UTC, to
// the microsecond the expiry check compares, with no trailing zeros in the
// fraction of a second and no fraction when it is zero. The proof expires at
// 2026-05-24T06:00:00Z and the clock is 2026-05-24T00:00:00Z.
// ../python/test_verify.py holds the same table.
var expiredReasons = []struct {
	expiresAt, clock, want string
}{
	{"", "2026-05-24T06:00:01Z", "expired at 2026-05-24T06:00:00Z, verifier clock is 2026-05-24T06:00:01Z"},
	{"", "2026-05-24T06:00:00.000001Z", "expired at 2026-05-24T06:00:00Z, verifier clock is 2026-05-24T06:00:00.000001Z"},  // a microsecond after the expiry time
	{"", "2026-05-24T06:00:00.0000019Z", "expired at 2026-05-24T06:00:00Z, verifier clock is 2026-05-24T06:00:00.000001Z"}, // the seventh digit dropped
	{"", "2026-05-24T06:00:00.500000Z", "expired at 2026-05-24T06:00:00Z, verifier clock is 2026-05-24T06:00:00.5Z"},
	{"", "2026-05-24T08:00:00.00001+02:00", "expired at 2026-05-24T06:00:00Z, verifier clock is 2026-05-24T06:00:00.00001Z"},
	{"2026-05-23T23:59:59.999999Z", "", "expired at 2026-05-23T23:59:59.999999Z, verifier clock is 2026-05-24T00:00:00Z"},
	{"0001-01-01T00:00:00Z", "", "expired at 0001-01-01T00:00:00Z, verifier clock is 2026-05-24T00:00:00Z"},
}

// TestExpiredReason: the EXPIRED reason writes the expiry time and the
// verifier's clock to the microsecond the expiry check compares, so a clock
// a microsecond after the expiry time does not read as the expiry time, and
// both verifiers give the same reason.
func TestExpiredReason(t *testing.T) {
	for _, tc := range expiredReasons {
		t.Run(tc.expiresAt+","+tc.clock, func(t *testing.T) {
			got := verify(baselineWithTimestamps(t, []string{"", tc.expiresAt, tc.clock}))
			if want := "REJECT[EXPIRED: " + tc.want + "]"; got.String() != want {
				t.Fatalf("got %s, want %s", got, want)
			}
		})
	}
}

// hexMembers lists hex members of committed ACCEPT fixtures, each with the
// REJECT category both verifiers return when an ASCII whitespace character
// is written after its tenth hex digit: a configured public key is then
// skipped, so no configured key verifies the signature, and a wire hash or
// a published key is refused. ../python/test_verify.py holds the same
// table.
var hexMembers = []struct {
	fixture, path, want string
}{
	{"transparency-log-sth.json", "verifierState.publicKeys.0.publicKeyHex", "SIGNATURE_INVALID"},
	{"trust-proof-baseline.json", "verifierState.publicKeys.0.publicKeyHex", "SIGNATURE_INVALID"},
	{"trust-proof-hybrid.json", "verifierState.publicKeys.0.publicKeyHex", "SIGNATURE_INVALID"},
	{"transparency-inclusion-proof-valid.json", "verifierState.publicKeys.0.publicKeyHex", "SIGNATURE_INVALID"},
	{"transparency-consistency-proof-valid.json", "verifierState.publicKeys.0.publicKeyHex", "SIGNATURE_INVALID"},
	{"transparency-log-sth.json", "signedTreeHead.rootHash", "STH_INVALID"},
	{"transparency-inclusion-proof-valid.json", "inclusionProof.leafHash", "PARSE_ERROR"},
	{"transparency-inclusion-proof-valid.json", "inclusionProof.auditPath.0", "PARSE_ERROR"},
	{"transparency-inclusion-proof-valid.json", "inclusionProof.signedTreeHead.rootHash", "STH_INVALID"},
	{"transparency-consistency-proof-valid.json", "consistencyProof.consistencyPath.0", "PARSE_ERROR"},
	{"transparency-consistency-proof-valid.json", "consistencyProof.fromSignedTreeHead.rootHash", "STH_INVALID"},
	{"discovery-valid.json", "discoveryResponse.publicKeys.0.publicKeyHex", "DISCOVERY_INVALID"},
	{"discovery-valid.json", "discoveryResponse.publicKeys.1.publicKeyHex", "DISCOVERY_INVALID"},
}

// asciiWhitespace lists the ASCII whitespace characters Python's
// bytes.fromhex skips between two bytes. ../python/test_verify.py holds the
// same list.
var asciiWhitespace = []string{" ", "\t", "\n", "\v", "\f", "\r"}

// withHexSpace returns value, a hex string with or without the "SHA256:"
// prefix, with space written after its tenth hex digit, between its fifth
// and sixth bytes.
func withHexSpace(value, space string) string {
	at := 10
	if strings.HasPrefix(value, "SHA256:") {
		at += len("SHA256:")
	}
	return value[:at] + space + value[at:]
}

// TestHexDigits: a hex value is read only as an even number of hex digits
// in either case, as hex.DecodeString reads it, which is what the Python
// verifier's _hex_bytes reads where bytes.fromhex alone skips ASCII
// whitespace between bytes. The member in upper case is read, and the
// fixture stays ACCEPT.
func TestHexDigits(t *testing.T) {
	for _, tc := range hexMembers {
		value := memberValue(t, tc.fixture, tc.path)
		for _, space := range asciiWhitespace {
			t.Run(tc.fixture+":"+tc.path+"="+strconv.Quote(space), func(t *testing.T) {
				got := verify(mutatedFixture(t, tc.fixture, tc.path, jsonString(t, withHexSpace(value, space))))
				if outcome(got) != tc.want {
					t.Fatalf("got %s, want %s", got, tc.want)
				}
			})
		}
		t.Run(tc.fixture+":"+tc.path+"=upper case", func(t *testing.T) {
			got := verify(mutatedFixture(t, tc.fixture, tc.path, jsonString(t, strings.ToUpper(value))))
			if !got.Accepted {
				t.Fatalf("got %s, want ACCEPT", got)
			}
		})
	}
}

// fixtureMembers leaves one member of trust-proof-baseline.json outside
// verifierState and the payload members out (literal "") or replaces it
// with the raw JSON literal, with the outcome both verifiers return: ACCEPT,
// the REJECT category, or "load error". ../python/test_verify.py holds the
// same table.
var fixtureMembers = []struct {
	path, literal, want string
}{
	{"name", "5", "load error"},
	{"name", "[]", "load error"},
	{"name", strings.Repeat("9", 5000), "load error"},
	{"name", "null", "ACCEPT"},
	{"name", "", "ACCEPT"},
	{"description", "5", "load error"},
	{"description", "{}", "load error"},
	{"fixtureType", "5", "load error"},
	{"fixtureType", `["trustProof"]`, "load error"},
	{"fixtureType", "null", "PARSE_ERROR"},
	{"keypairRefs", `"issuer-primary"`, "load error"},
	{"keypairRefs", "{}", "load error"},
	{"keypairRefs", "[5]", "load error"},
	{"keypairRefs.0.publicKeyHex", "5", "load error"},
	{"keypairRefs", "null", "ACCEPT"},
	{"keypairRefs.0", "null", "ACCEPT"},
	{"expected", "5", "load error"},
	{"expected", "[]", "load error"},
	{"expected", `"ACCEPT"`, "load error"},
	{"expected.verifyResult", "5", "load error"},
	{"expected.verifyResult", "true", "load error"},
	{"expected.rejectCategory", "5", "load error"},
	{"expected.reasonContains", "[]", "load error"},
	{"expected", "null", "ACCEPT"},
	{"expected.verifyResult", "null", "ACCEPT"},
}

// TestFixtureMember: parseFixture decodes name, description, fixtureType,
// keypairRefs and expected with encoding/json into the fixture struct, so a
// member of the wrong JSON type is a load error, and an absent or null
// member is its zero value, which leaves the verdict to the verification
// steps: the outcome the Python verifier returns for the same input. The
// unmodified fixture verifies ACCEPT (TestSchemaTypeViolationIsParseError
// checks it).
func TestFixtureMember(t *testing.T) {
	for _, tc := range fixtureMembers {
		t.Run(tc.path+"="+shortLiteral(tc.literal), func(t *testing.T) {
			doc, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "trust-proof-baseline.json"))
			if err != nil {
				t.Fatal(err)
			}
			path := strings.Split(tc.path, ".")
			if tc.literal == "" {
				doc = renameMember(t, doc, path, "")
			} else {
				doc = setMember(t, doc, path, tc.literal)
			}
			f, err := parseFixture(doc)
			if err != nil {
				if tc.want != "load error" {
					t.Fatalf("load error %v, want %s", err, tc.want)
				}
				return
			}
			if got := verify(f); outcome(got) != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// modulePath is where this module lives. `go run <modulePath>@latest`, the
// README's first command, fails when go.mod declares any other path.
const modulePath = "github.com/opena2a-standards/atp-conformance/verifiers/go"

// TestModulePathIsTheReadmeEntryPoint: go.mod declares modulePath and the
// README's first command runs it at @latest.
func TestModulePathIsTheReadmeEntryPoint(t *testing.T) {
	mod, err := fs.ReadFile(os.DirFS("."), "go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if first, _, _ := strings.Cut(string(mod), "\n"); first != "module "+modulePath {
		t.Errorf("go.mod declares %q, want %q", first, "module "+modulePath)
	}

	readme, err := fs.ReadFile(os.DirFS(filepath.Join("..", "..")), "README.md")
	if err != nil {
		t.Fatal(err)
	}
	command := ""
	lines := strings.Split(string(readme), "\n")
	for i := 0; i+1 < len(lines); i++ {
		if strings.HasPrefix(lines[i], "```") {
			command = lines[i+1]
			break
		}
	}
	if want := "go run " + modulePath + "@latest"; command != want {
		t.Errorf("README's first command is %q, want %q", command, want)
	}
}

// TestFixtureGeneratorModulePath: the fixture generator's go.mod declares
// its directory under the same repository path as modulePath, so `go run
// <path>@<version>` resolves it as it resolves this module.
func TestFixtureGeneratorModulePath(t *testing.T) {
	const dir = "scripts/generate-fixtures"
	mod, err := fs.ReadFile(os.DirFS(filepath.Join("..", "..", dir)), "go.mod")
	if err != nil {
		t.Fatal(err)
	}
	want := "module " + strings.TrimSuffix(modulePath, "/verifiers/go") + "/" + dir
	if first, _, _ := strings.Cut(string(mod), "\n"); first != want {
		t.Errorf("%s/go.mod declares %q, want %q", dir, first, want)
	}
}

// TestBuiltinFixturesAreTheFixturesDirectory: the set a run with no
// arguments verifies holds the same files as ../../fixtures, byte for byte.
// scripts/parity/parity.py makes the same check in CI.
func TestBuiltinFixturesAreTheFixturesDirectory(t *testing.T) {
	repo := os.DirFS(filepath.Join("..", ".."))
	want, err := fs.Glob(repo, "fixtures/*.json")
	if err != nil || len(want) == 0 {
		t.Fatalf("../../fixtures/*.json: %d files, err %v", len(want), err)
	}
	got, err := builtinFixturePaths()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("built-in set %v, ../../fixtures holds %v", got, want)
	}
	for _, name := range want {
		committed, err := fs.ReadFile(repo, name)
		if err != nil {
			t.Fatal(err)
		}
		builtin, err := builtinFixtures.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(builtin, committed) {
			t.Errorf("built-in %s differs from ../../%s", name, name)
		}
	}
}

// TestBuiltinFixturesPass verifies the built-in set the way a run with no
// arguments does and expects every fixture to pass.
func TestBuiltinFixturesPass(t *testing.T) {
	paths, err := builtinFixturePaths()
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	pass, fail := verifyAll(&out, paths, loadBuiltinFixture, func(p string) string { return p })
	if pass == 0 || fail != 0 || pass != len(paths) {
		t.Fatalf("%d pass, %d fail over %d built-in fixtures\n%s", pass, fail, len(paths), out.String())
	}
	if want := fmt.Sprintf("summary: %d pass, 0 fail (%d fixtures)\n", pass, pass); !strings.HasSuffix(out.String(), want) {
		t.Errorf("output does not end with %q", want)
	}
}
