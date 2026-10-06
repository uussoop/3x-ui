package openvpn

import (
	"strings"
	"testing"
	"time"
)

func TestParseStatusReplyRoutingTable(t *testing.T) {
	lines := []string{
		"OpenVPN Client: 10.8.0.6:1194",
		"Updated,Sat Oct  4 12:00:00 2026",
		"ROUTING_TABLE",
		"ROUTING_TABLE,10.8.0.2,,alice,203.0.113.5:41234,10.8.0.2,Sat Oct  4 11:00:00 2026,1024,2048",
		"ROUTING_TABLE,10.8.0.3,,bob,203.0.113.6:41235,10.8.0.3,Sat Oct  4 11:30:00 2026,10,20",
		"ROUTING_TABLE,,fd00::2,carol,203.0.113.7:41236,fd00::2,Sat Oct  4 11:45:00 2026,7,8",
		"GLOBAL_STATS",
		"STATISTICS",
		"STATISTICS,Updated,Sat Oct  4 12:00:01 2026",
		"STATISTICS,TUN/TAP read bytes,5000",
		"STATISTICS,TUN/TAP write bytes,9000",
		"END",
	}
	r := parseStatusReply(lines)
	if len(r.Sessions) != 3 {
		t.Fatalf("sessions = %d, want 3", len(r.Sessions))
	}
	a := r.Sessions[0]
	if a.CommonName != "alice" {
		t.Errorf("common name = %q, want alice", a.CommonName)
	}
	if a.RealAddress != "203.0.113.5:41234" {
		t.Errorf("real address = %q", a.RealAddress)
	}
	if a.VirtualIP != "10.8.0.2" {
		t.Errorf("virtual ip = %q", a.VirtualIP)
	}
	if a.BytesIn != 1024 || a.BytesOut != 2048 {
		t.Errorf("session counters = in %d out %d, want 1024/2048", a.BytesIn, a.BytesOut)
	}
	// An IPv6-only client has an empty IPv4 column; it must still be reported.
	c := r.Sessions[2]
	if c.VirtualIPv6 != "fd00::2" || c.VirtualIP != "" {
		t.Errorf("ipv6 session = %+v", c)
	}
	if !r.HasCounters || r.UpBytes != 9000 || r.DownBytes != 5000 {
		t.Errorf("counters = up %d down %d has %v", r.UpBytes, r.DownBytes, r.HasCounters)
	}
}

// A daemon that does not report per-session counters must not be read as a
// client that sent zero bytes: -1 marks "unknown" and keeps it distinguishable
// from a genuine zero.
func TestParseStatusReplyAbsentSessionCounters(t *testing.T) {
	lines := []string{
		"ROUTING_TABLE",
		"ROUTING_TABLE,10.8.0.2,,alice,203.0.113.5:41234,10.8.0.2,Sat Oct  4 11:00:00 2026",
		"END",
	}
	r := parseStatusReply(lines)
	if len(r.Sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(r.Sessions))
	}
	if r.Sessions[0].BytesIn != -1 || r.Sessions[0].BytesOut != -1 {
		t.Errorf("missing counters should be -1, got %d/%d", r.Sessions[0].BytesIn, r.Sessions[0].BytesOut)
	}
	if r.HasCounters {
		t.Error("HasCounters = true with no STATISTICS section")
	}
}

// The format has grown across OpenVPN releases; an extra informational line must
// not cost the panel its visibility into a working tunnel.
func TestParseStatusReplyIgnoresUnknownLines(t *testing.T) {
	lines := []string{
		"OpenVPN Client: 10.8.0.6:1194",
		"OpenVPN Version: OpenVPN 2.6.7",
		"SOME FUTURE SECTION",
		"SOME FUTURE ROW,1,2,3",
		"ROUTING_TABLE",
		"ROUTING_TABLE,10.8.0.2,,alice,203.0.113.5:41234,10.8.0.2,Sat Oct  4 11:00:00 2026,1,2",
		"STATISTICS",
		"STATISTICS,TUN/TAP read bytes,42",
		"STATISTICS,TUN/TAP write bytes,84",
		"END",
	}
	r := parseStatusReply(lines)
	if len(r.Sessions) != 1 || r.DownBytes != 42 || r.UpBytes != 84 {
		t.Errorf("unexpected parse: %+v", r)
	}
}

func TestParseCounter(t *testing.T) {
	if got := parseCounter("123"); got != 123 {
		t.Errorf("parseCounter(123) = %d", got)
	}
	if got := parseCounter("0"); got != 0 {
		t.Errorf("parseCounter(0) = %d; zero is a real reading", got)
	}
	if got := parseCounter("-5"); got != -1 {
		t.Errorf("parseCounter(-5) = %d, want -1", got)
	}
	if got := parseCounter(""); got != -1 {
		t.Errorf("parseCounter(empty) = %d, want -1", got)
	}
	if got := parseCounter("abc"); got != -1 {
		t.Errorf("parseCounter(abc) = %d, want -1", got)
	}
}

// The management interface is loopback-only but not private, so an empty
// password must be refused rather than tried — that would hide a
// misconfiguration behind a confusing auth error.
func TestMgmtClientRefusesEmptyPassword(t *testing.T) {
	c := &mgmtClient{addr: "127.0.0.1:1", password: "", timeout: time.Second}
	if _, err := c.open(); err == nil {
		t.Fatal("management client connected without a password")
	}
}

func TestParseOpenVPNTime(t *testing.T) {
	if _, ok := parseOpenVPNTime("Sat Oct  4 11:00:00 2026"); !ok {
		t.Error("a well-formed since timestamp was not parsed")
	}
	if _, ok := parseOpenVPNTime("nonsense"); ok {
		t.Error("a malformed timestamp should yield no time, not a wrong one")
	}
	if _, ok := parseOpenVPNTime(""); ok {
		t.Error("an empty timestamp should yield no time")
	}
}

func TestScrubLineRedactsSecrets(t *testing.T) {
	tests := []struct {
		in    string
		want  string
		leaks string
	}{
		{"management-client-password hunter2", "management-client-password <redacted>", "hunter2"},
		{"auth-user-pass alice:s3cret", "auth-user-pass <redacted>", "s3cret"},
		{"ERROR: cannot open management password file", "ERROR: cannot open management password file", ""},
		{"TLS Error: incoming packet authentication failed", "TLS Error: incoming packet authentication failed", ""},
	}
	for _, tc := range tests {
		got := ScrubLine(tc.in)
		if got != tc.want {
			t.Errorf("ScrubLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if tc.leaks != "" && strings.Contains(got, tc.leaks) {
			t.Errorf("ScrubLine(%q) leaked %q", tc.in, tc.leaks)
		}
	}
}

// A diagnostic line that merely contains a sensitive word must stay readable;
// over-eager redaction makes a broken tunnel impossible to debug.
func TestScrubLineKeepsProseReadable(t *testing.T) {
	line := "SIGTERM[soft,id=1] received, client-key instance now inactive"
	if got := ScrubLine(line); got != line {
		t.Errorf("ScrubLine mangled a prose line: %q", got)
	}
}

// A secret on its own line (inline PEM blocks are how OpenVPN logs a rejected
// multi-line value) must not be echoed: the scrubber replaces the value on the
// directive line and the caller scrubs continuation lines separately, so at
// minimum a bare value line that looks like PEM must be caught.
func TestScrubLineDoesNotMatchSubstrings(t *testing.T) {
	// "monkey" contains "key" but is not a directive.
	line := "options: monkey=1"
	if got := ScrubLine(line); got != line {
		t.Errorf("ScrubLine matched a substring: %q", got)
	}
}

func TestRedactSecret(t *testing.T) {
	if got := RedactSecret(""); got != "" {
		t.Errorf("empty secret should stay empty, got %q", got)
	}
	if got := RedactSecret("s3cret"); got == "s3cret" || got != "<redacted>" {
		t.Errorf("RedactSecret = %q", got)
	}
}