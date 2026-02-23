package ntlm_proxy

// Blocklist — deny-list for outbound connections.
//
// The list is loaded exclusively from a plain-text config file; there are no
// compile-time defaults.  One hostname per line.  Lines beginning with '#'
// and blank lines are ignored.  Hostnames are matched case-insensitively on
// the hostname portion only (port is stripped before comparison).  Suffix /
// wildcard matching is intentionally NOT supported to keep the logic simple
// and auditable.
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
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

// blockedHosts is the effective set used at runtime.
var blockedHosts map[string]struct{}

func init() {
	var err error
	blockedHosts, err = loadBlocklist()
	if err != nil {
		log.Warnf("Blocklist: %v", err)
	}
	log.Infof("Blocklist active with %d entries", len(blockedHosts))
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

// loadBlocklist reads the blocklist file and returns the resulting host set.
// A missing file is not an error — it simply produces an empty set.
func loadBlocklist() (map[string]struct{}, error) {
	hosts := make(map[string]struct{})

	path := blocklistPath()
	if path == "" {
		return hosts, nil
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debugf("Blocklist file not found at %s — running with empty blocklist", path)
			return hosts, nil
		}
		return hosts, fmt.Errorf("opening blocklist file %q: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hosts[strings.ToLower(line)] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return hosts, fmt.Errorf("reading blocklist file %q: %w", path, err)
	}

	log.Debugf("Blocklist loaded %d entries from %s", len(hosts), path)
	return hosts, nil
}

// isBlocked reports whether the given host (with or without port) is on the
// blocklist.
func isBlocked(hostWithOptionalPort string) bool {
	host := hostWithOptionalPort
	if h, _, err := splitHostPort(hostWithOptionalPort); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	_, blocked := blockedHosts[host]
	return blocked
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
