package main

import (
	"encoding/json"
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
