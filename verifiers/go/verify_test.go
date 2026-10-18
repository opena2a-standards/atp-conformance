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
