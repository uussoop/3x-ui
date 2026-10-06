//go:build !race

package openvpn

import (
	"strings"
	"testing"
)

var allowedServerOptions = map[string]struct{}{
	"auth-user-pass-verify":   {},
	"ca":                      {},
	"cert":                    {},
	"client-config-dir":       {},
	"dev":                     {},
	"dev-type":                {},
	"dh":                      {},
	"keepalive":               {},
	"key":                     {},
	"management":              {},
	"mode":                    {},
	"persist-key":             {},
	"persist-tun":             {},
	"ping-restart":            {},
	"proto":                   {},
	"push":                    {},
	"script-security":         {},
	"server":                  {},
	"topology":                {},
	"tls-server":              {},
	"username-as-common-name": {},
	"verb":                    {},
	"verify-client-cert":      {},
}

var allowedClientOptions = map[string]struct{}{
	"auth":             {},
	"ca":               {},
	"cert":             {},
	"cipher":           {},
	"client":           {},
	"comp-lzo":         {},
	"dev":              {},
	"dev-type":         {},
	"float":            {},
	"keepalive":        {},
	"key":              {},
	"management":       {},
	"nobind":           {},
	"persist-key":      {},
	"persist-tun":      {},
	"proto":            {},
	"redirect-gateway": {},
	"remote":           {},
	"remote-cert-tls":  {},
	"resolv-retry":     {},
	"script-security":  {},
	"tls-auth":         {},
	"tls-version-min":  {},
	"block-ipv6":       {},
	"connect-retry":    {}, "verb": {},
	"verify-x509-name": {},
	"auth-user-pass":   {}}

func isCommentOrEmpty(s string) bool {
	ss := strings.TrimSpace(s)
	return ss == "" || strings.HasPrefix(ss, "#")
}

func firstToken(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i > 0 {
		return s[:i]
	}
	return s
}

func TestRenderServerConfigUsesOnlyVerifiedOptions(t *testing.T) {
	inst := serverInstance()
	inst.DNSServer = "10.8.0.1"
	cfg := RenderServerConfig(inst)
	for _, line := range strings.Split(cfg, "\n") {
		if isCommentOrEmpty(line) {
			continue
		}
		tok := firstToken(line)
		if _, ok := allowedServerOptions[tok]; !ok {
			t.Errorf("server config emits unverified option %q: %s", tok, line)
		}
	}
}

func TestRenderClientConfigUsesOnlyVerifiedOptions(t *testing.T) {
	inst := leakExit(t)
	prof, err := ParseProfile(goodProfile)
	if err != nil {
		t.Fatalf("ParseProfile: %v", err)
	}
	cfg := RenderClientConfig(inst, prof)
	for _, line := range strings.Split(cfg, "\n") {
		if isCommentOrEmpty(line) {
			continue
		}
		tok := firstToken(line)
		if _, ok := allowedClientOptions[tok]; !ok {
			t.Errorf("client config emits unverified option %q: %s", tok, line)
		}
	}
}
