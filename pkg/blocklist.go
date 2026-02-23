package ntlm_proxy

// Blocklist — deny-list for outbound connections.
//
// The list is loaded exclusively from a plain-text config file; there are no
// compile-time defaults.  One hostname (or pattern) per line.  Lines
// beginning with '#' and blank lines are ignored.  Hostnames are matched
// case-insensitively on the hostname portion only (port is stripped before
// comparison).
//
// Pattern support:
//   - Entries containing '*' are treated as glob patterns (path.Match syntax).
//   - Example: *.opencode.ai blocks app.opencode.ai but NOT opencode.ai itself.
//   - To block both, add two entries: *.opencode.ai and opencode.ai.
//   - Invalid patterns are logged as warnings and skipped.
//
// Config file resolution order (first match wins):
//  1. GONTLM_BLOCKLIST_FILE environment variable (explicit path)
//  2. $HOME/.config/gontlm-proxy/blocklist
//
// If no file is found, the blocklist is empty and all traffic passes through.

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

// blockedHosts is the set of exact hostnames blocked at runtime.
var blockedHosts map[string]struct{}

// blockedPatterns is the list of glob patterns (entries containing '*') used
// to match hostnames at runtime.
var blockedPatterns []string

func init() {
	var err error
	blockedHosts, blockedPatterns, err = loadBlocklist()
	if err != nil {
		log.Warnf("Blocklist: %v", err)
	}
	log.Infof("Blocklist active with %d exact entries and %d patterns", len(blockedHosts), len(blockedPatterns))
}

// blocklistPath returns the path to the blocklist config file.
func blocklistPath() string {
	if p := os.Getenv("GONTLM_BLOCKLIST_FILE"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "gontlm-proxy", "blocklist")
}

// loadBlocklist reads the blocklist file and returns the resulting host set
// and pattern slice.  A missing file is not an error — it simply produces
// empty results.
func loadBlocklist() (hosts map[string]struct{}, patterns []string, err error) {
	hosts = make(map[string]struct{})

	p := blocklistPath()
	if p == "" {
		return hosts, patterns, nil
	}

	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debugf("Blocklist file not found at %s — running with empty blocklist", p)
			return hosts, patterns, nil
		}
		return hosts, patterns, fmt.Errorf("opening blocklist file %q: %w", p, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "*") {
			// Validate the pattern before accepting it.
			if _, matchErr := path.Match(lower, ""); matchErr != nil {
				log.Warnf("Blocklist: invalid pattern %q: %v — skipping", line, matchErr)
				continue
			}
			patterns = append(patterns, lower)
		} else {
			hosts[lower] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return hosts, patterns, fmt.Errorf("reading blocklist file %q: %w", p, err)
	}

	log.Debugf("Blocklist loaded %d exact entries and %d patterns from %s", len(hosts), len(patterns), p)
	return hosts, patterns, nil
}

// isBlocked reports whether the given host (with or without port) is on the
// blocklist.  Exact entries are checked first (O(1)); glob patterns are
// checked only when no exact match is found.
func isBlocked(hostWithOptionalPort string) bool {
	host := hostWithOptionalPort
	if h, _, err := splitHostPort(hostWithOptionalPort); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	if _, blocked := blockedHosts[host]; blocked {
		return true
	}

	for _, pattern := range blockedPatterns {
		if matched, _ := path.Match(pattern, host); matched {
			return true
		}
	}
	return false
}

// splitHostPort strips the port from an address, returning an error if there
// is no port component.
func splitHostPort(addr string) (host, port string, err error) {
	if !strings.Contains(addr, ":") {
		return addr, "", fmt.Errorf("no port")
	}
	last := strings.LastIndex(addr, ":")
	return addr[:last], addr[last+1:], nil
}

// blockResponse returns a 403 Forbidden response for a blocked host.
func blockResponse(req *http.Request) *http.Response {
	return &http.Response{
		StatusCode: http.StatusForbidden,
		Status:     "403 Forbidden (blocked by gontlm-proxy policy)",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       http.NoBody,
		Request:    req,
	}
}
