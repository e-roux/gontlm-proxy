package ntlm_proxy

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// writeBlocklistFile creates a temporary blocklist file with the given content
// and sets GONTLM_BLOCKLIST_FILE to point to it.  The file and env var are
// cleaned up automatically via t.Cleanup / t.Setenv.
func writeBlocklistFile(t *testing.T, content string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "blocklist-*")
	if err != nil {
		t.Fatalf("creating temp blocklist file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writing temp blocklist file: %v", err)
	}
	f.Close()
	t.Setenv("GONTLM_BLOCKLIST_FILE", f.Name())
}

// loadFresh calls loadBlocklist() and stores the results in the package-level
// blockedHosts and blockedPatterns so that isBlocked() uses them.
func loadFresh(t *testing.T) {
	t.Helper()
	hosts, patterns, err := loadBlocklist()
	if err != nil {
		t.Fatalf("loadBlocklist: %v", err)
	}
	blockedHosts = hosts
	blockedPatterns = patterns
}

// ----------------------------------------------------------------------------
// splitHostPort
// ----------------------------------------------------------------------------

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{"host with port", "example.com:443", "example.com", "443", false},
		{"host without port", "example.com", "example.com", "", true},
		{"IPv6 with port", "[::1]:8080", "[::1]", "8080", false},
		{"empty string", "", "", "", true},
		{"only colon", ":", "", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, port, err := splitHostPort(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("splitHostPort(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
			if host != tc.wantHost {
				t.Errorf("host = %q, want %q", host, tc.wantHost)
			}
			if port != tc.wantPort {
				t.Errorf("port = %q, want %q", port, tc.wantPort)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// loadBlocklist — file parsing
// ----------------------------------------------------------------------------

func TestLoadBlocklist_BasicEntries(t *testing.T) {
	writeBlocklistFile(t, `
# opencode endpoints
opncd.ai
app.opencode.ai

# npm
registry.npmjs.org
`)
	loadFresh(t)

	for _, h := range []string{"opncd.ai", "app.opencode.ai", "registry.npmjs.org"} {
		if !isBlocked(h) {
			t.Errorf("expected %q to be blocked", h)
		}
	}
}

func TestLoadBlocklist_CommentsAndBlanksIgnored(t *testing.T) {
	writeBlocklistFile(t, `
# this is a comment
   # indented comment

example.com
# another comment
other.com
`)
	loadFresh(t)

	if !isBlocked("example.com") {
		t.Error("expected example.com to be blocked")
	}
	if !isBlocked("other.com") {
		t.Error("expected other.com to be blocked")
	}
	// Comments must not appear as hosts.
	if isBlocked("# this is a comment") {
		t.Error("comment line must not be a blocked host")
	}
}

func TestLoadBlocklist_CaseNormalised(t *testing.T) {
	writeBlocklistFile(t, "OPNCD.AI\nMcp.Exa.AI\n")
	loadFresh(t)

	for _, h := range []string{"opncd.ai", "OPNCD.AI", "mcp.exa.ai", "MCP.EXA.AI"} {
		if !isBlocked(h) {
			t.Errorf("expected %q to be blocked (case-insensitive)", h)
		}
	}
}

func TestLoadBlocklist_EmptyFile(t *testing.T) {
	writeBlocklistFile(t, "")
	loadFresh(t)

	if isBlocked("opncd.ai") {
		t.Error("empty file should produce empty blocklist")
	}
}

func TestLoadBlocklist_MissingFile_NotAnError(t *testing.T) {
	t.Setenv("GONTLM_BLOCKLIST_FILE", filepath.Join(t.TempDir(), "nonexistent"))

	hosts, patterns, err := loadBlocklist()
	if err != nil {
		t.Errorf("missing file should not be an error, got: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("missing file should yield empty set, got %d entries", len(hosts))
	}
	if len(patterns) != 0 {
		t.Errorf("missing file should yield empty patterns, got %d", len(patterns))
	}
}

func TestLoadBlocklist_NoEnvVar_NoHomeConfig_Empty(t *testing.T) {
	// Clear the env var and point HOME somewhere that has no config.
	t.Setenv("GONTLM_BLOCKLIST_FILE", "")
	t.Setenv("HOME", t.TempDir())

	hosts, patterns, err := loadBlocklist()
	if err != nil {
		t.Errorf("no config should not error: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("no config should yield empty set, got %d", len(hosts))
	}
	if len(patterns) != 0 {
		t.Errorf("no config should yield empty patterns, got %d", len(patterns))
	}
}

// ----------------------------------------------------------------------------
// isBlocked — behaviour via loaded file
// ----------------------------------------------------------------------------

func TestIsBlocked_WithPort(t *testing.T) {
	writeBlocklistFile(t, "opncd.ai\nmcp.exa.ai\n")
	loadFresh(t)

	for _, addr := range []string{"opncd.ai:443", "mcp.exa.ai:443"} {
		if !isBlocked(addr) {
			t.Errorf("expected %q to be blocked (host:port form)", addr)
		}
	}
}

func TestIsBlocked_AllowedHosts(t *testing.T) {
	writeBlocklistFile(t, "opncd.ai\n")
	loadFresh(t)

	for _, h := range []string{"bosch.com", "aoai-farm.bosch-temp.com", "localhost", "127.0.0.1", ""} {
		if isBlocked(h) {
			t.Errorf("expected %q to be allowed", h)
		}
	}
}

func TestIsBlocked_NoSubdomainMatch_ExactEntry(t *testing.T) {
	// An exact entry does NOT match subdomains — use a pattern for that.
	writeBlocklistFile(t, "opncd.ai\nmodels.dev\n")
	loadFresh(t)

	for _, h := range []string{"sub.opncd.ai", "api.models.dev", "notopncd.ai"} {
		if isBlocked(h) {
			t.Errorf("expected %q to be allowed (exact entry, no subdomain match)", h)
		}
	}
}

// ----------------------------------------------------------------------------
// Wildcard / glob pattern matching
// ----------------------------------------------------------------------------

func TestIsBlocked_WildcardPattern_BlocksSubdomains(t *testing.T) {
	writeBlocklistFile(t, "*.opencode.ai\n")
	loadFresh(t)

	blocked := []string{"app.opencode.ai", "api.opencode.ai", "www.opencode.ai"}
	for _, h := range blocked {
		if !isBlocked(h) {
			t.Errorf("expected %q to be blocked by *.opencode.ai", h)
		}
	}
}

func TestIsBlocked_WildcardPattern_DoesNotBlockApex(t *testing.T) {
	// *.opencode.ai must NOT match the apex domain opencode.ai.
	writeBlocklistFile(t, "*.opencode.ai\n")
	loadFresh(t)

	if isBlocked("opencode.ai") {
		t.Error("*.opencode.ai must not block the apex domain opencode.ai")
	}
}

func TestIsBlocked_WildcardPattern_WithPort(t *testing.T) {
	writeBlocklistFile(t, "*.opencode.ai\n")
	loadFresh(t)

	if !isBlocked("app.opencode.ai:443") {
		t.Error("expected app.opencode.ai:443 to be blocked by *.opencode.ai")
	}
}

func TestIsBlocked_WildcardPattern_CaseInsensitive(t *testing.T) {
	writeBlocklistFile(t, "*.OpenCode.AI\n")
	loadFresh(t)

	if !isBlocked("APP.opencode.ai") {
		t.Error("expected APP.opencode.ai to be blocked (case-insensitive pattern)")
	}
}

func TestIsBlocked_WildcardPattern_DoesNotMatchUnrelated(t *testing.T) {
	writeBlocklistFile(t, "*.opencode.ai\n")
	loadFresh(t)

	unrelated := []string{"opencode.com", "notopencode.ai", "bosch.com"}
	for _, h := range unrelated {
		if isBlocked(h) {
			t.Errorf("expected %q to be allowed (unrelated to *.opencode.ai)", h)
		}
	}
}

func TestIsBlocked_ExactAndWildcard_Together(t *testing.T) {
	// opencode.ai (exact) + *.opencode.ai (wildcard) — both should be blocked.
	writeBlocklistFile(t, "opencode.ai\n*.opencode.ai\n")
	loadFresh(t)

	for _, h := range []string{"opencode.ai", "app.opencode.ai", "api.opencode.ai"} {
		if !isBlocked(h) {
			t.Errorf("expected %q to be blocked", h)
		}
	}
}

func TestLoadBlocklist_InvalidPattern_Skipped(t *testing.T) {
	// A pattern with an unmatched '[' is invalid per path.Match.
	writeBlocklistFile(t, "valid.com\n*.[invalid\ngood.com\n")
	loadFresh(t)

	if !isBlocked("valid.com") {
		t.Error("valid.com should be blocked")
	}
	if !isBlocked("good.com") {
		t.Error("good.com should be blocked")
	}
	// The invalid pattern must not have been stored.
	if len(blockedPatterns) != 0 {
		t.Errorf("invalid pattern should have been skipped, got %d patterns", len(blockedPatterns))
	}
}

func TestIsBlocked_EmptyBlocklist_AllowsAll(t *testing.T) {
	writeBlocklistFile(t, "")
	loadFresh(t)

	for _, h := range []string{"opncd.ai", "registry.npmjs.org", "mcp.exa.ai"} {
		if isBlocked(h) {
			t.Errorf("empty blocklist: expected %q to be allowed", h)
		}
	}
}

// ----------------------------------------------------------------------------
// blockResponse
// ----------------------------------------------------------------------------

func TestBlockResponse(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://opncd.ai/", nil)
	resp := blockResponse(req)

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if resp.Body == nil {
		t.Error("Body must not be nil")
	}
	if resp.Request != req {
		t.Error("Response.Request must point back to the original request")
	}
	if resp.ProtoMajor != 1 || resp.ProtoMinor != 1 {
		t.Errorf("Proto = %d.%d, want 1.1", resp.ProtoMajor, resp.ProtoMinor)
	}
}
