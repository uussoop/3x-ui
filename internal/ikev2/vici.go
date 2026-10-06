package ikev2

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// VICI is strongSwan's control protocol: length-prefixed messages over a UNIX
// socket. Requests are newline-terminated INI-style sections; replies are the
// same plus an "OK"/"ERROR" terminator. Events are pushed asynchronously, which
// is why reads are guarded — a concurrent poll and a config load must not
// interleave on one connection.
//
// Only the commands the panel needs are modelled: load/unload of connections,
// certificates and PSKs, initiation and termination, and the event stream that
// carries child-SAs and their byte counters.
type VICI struct {
	mu      sync.Mutex
	conn    net.Conn
	r       *bufio.Reader
	w       *bufio.Writer
	path    string
	timeout time.Duration
	closed  bool
}

// viciMsgType values used by the panel. The full protocol has more types; only
// these are needed.
const (
	viciTypeRequest  byte = 1
	viciTypeResponse byte = 2
	viciTypeEvent    byte = 3
)

// DialVICI connects to strongSwan's VICI socket.
//
// The socket is opened with the panel's own credentials only. charon's VICI
// interface grants full control over the IPsec configuration — including
// loading private keys — so it must never be reachable by anything but the
// panel.
func DialVICI(path string, timeout time.Duration) (*VICI, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("no VICI socket path configured")
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("connect to strongSwan VICI socket: %w", err)
	}
	v := &VICI{
		conn:    conn,
		r:       bufio.NewReader(conn),
		w:       bufio.NewWriter(conn),
		path:    path,
		timeout: timeout,
	}
	return v, nil
}

// Close releases the socket.
func (v *VICI) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	return v.conn.Close()
}

// Section is one block of a VICI message: a section name plus ordered key/value
// pairs, preserving the nesting strongSwan uses for repeated keys.
type Section struct {
	Name  string
	Keys  []string
	Values []string
}

// Set appends a key/value pair.
func (s *Section) Set(key, value string) {
	s.Keys = append(s.Keys, key)
	s.Values = append(s.Values, value)
}

// encode renders a request as the newline-terminated INI form VICI expects:
// "name = {key = value ...}" per section.
//
// Values are wrapped in double quotes and escaped, because they routinely carry
// PEM blocks with newlines — an unescaped newline would terminate the key and
// turn a private key into a syntax error at best, or a second directive at
// worst.
func encode(sections []Section) string {
	var b strings.Builder
	for _, s := range sections {
		b.WriteString(s.Name)
		b.WriteString(" = {")
		for i, k := range s.Keys {
			b.WriteString("\n")
			b.WriteString(k)
			b.WriteString(" = ")
			b.WriteString(quoteValue(s.Values[i]))
		}
		b.WriteString("\n}\n")
	}
	return b.String()
}

func quoteValue(v string) string {
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"\"", "\\\"",
		"\n", "\\n",
		"\r", "\\r",
	)
	return "\"" + replacer.Replace(v) + "\""
}

// Send writes a request and reads the reply, returning the sections of a
// successful response.
//
// Events that arrive before the reply are skipped rather than mixed in: the
// panel polls on a timer, and treating an unsolicited child-SA notification as a
// command result would make a config load look like a failure.
func (v *VICI) Send(sections []Section) ([]Section, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, errors.New("VICI connection is closed")
	}
	payload := encode(sections)
	// The deadline is per request, not per connection. Setting it once at dial
	// would make the socket permanently unusable a few seconds later, which for a
	// control socket the panel holds open for the life of the daemon looks like a
	// tunnel that stopped responding.
	if v.timeout > 0 {
		_ = v.conn.SetDeadline(time.Now().Add(v.timeout))
		defer func() { _ = v.conn.SetDeadline(time.Time{}) }()
	}
	// A request is framed exactly like a reply: the 12-byte header precedes the
	// payload. charon reads the header first, so an unframed payload would be
	// interpreted as a message whose length is taken from the section name.
	if err := v.writeMessage(viciTypeRequest, payload); err != nil {
		return nil, err
	}
	for {
		reply, err := v.readMessage()
		if err != nil {
			return nil, err
		}
		if reply.typ == viciTypeEvent {
			continue
		}
		if msg := replyText(reply); msg != "" {
			return nil, errors.New(strings.TrimSpace(msg))
		}
		return reply.sections, nil
	}
}

// writeMessage frames and flushes one request. group, version and command id
// stay zero: charon accepts a request that leaves them unset and fills them in on
// the reply, and the panel has no use for pairing.
func (v *VICI) writeMessage(typ byte, payload string) error {
	body := []byte(payload)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint32(hdr[0:4], uint32(len(hdr)+len(body)))
	hdr[4] = typ
	if _, err := v.w.Write(hdr); err != nil {
		return err
	}
	if _, err := v.w.Write(body); err != nil {
		return err
	}
	return v.w.Flush()
}

type message struct {
	typ      byte
	sections []Section
}

// replyText returns a VICI error as a message. The human-readable message is
// preferred over the kind: the kind is a constant like NO_CHILD_SA, and an
// operator — or a substring check deciding whether "the SA is already gone" —
// needs the actual reason.
func replyText(m message) string {
	for _, s := range m.sections {
		if !strings.EqualFold(s.Name, "error") {
			continue
		}
		if msg := s.get("message"); msg != "" {
			return msg
		}
		if kind := s.get("kind"); kind != "" {
			return kind
		}
		return "VICI error"
	}
	return ""
}

// readMessage reads one framed VICI message. The header is 12 bytes: length,
// type, flags, two reserved bytes, group, version, and a command id.
func (v *VICI) readMessage() (message, error) {
	var hdr [12]byte
	if _, err := io.ReadFull(v.r, hdr[:]); err != nil {
		return message{}, err
	}
	length := binary.BigEndian.Uint32(hdr[0:4])
	if length < uint32(len(hdr)) {
		return message{}, fmt.Errorf("VICI message length %d is shorter than its header", length)
	}
	payload := make([]byte, length-uint32(len(hdr)))
	if _, err := io.ReadFull(v.r, payload); err != nil {
		return message{}, err
	}
	return message{typ: hdr[4], sections: parseSections(string(payload))}, nil
}

// parseSections parses VICI's INI-style payload. Sections are "name = {",
// keys are "key = value", and a section ends with "}". A line with no "=" opens
// a nested anonymous block, which the panel does not use.
func parseSections(payload string) []Section {
	var out []Section
	var cur *Section
	for _, raw := range strings.Split(payload, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "}"):
			if cur != nil {
				out = append(out, *cur)
				cur = nil
			}
		case line == "{":
			// Anonymous nested block: the panel has no use for one, so it is
			// skipped rather than guessed at.
		case strings.Contains(line, "{"):
			name, _, _ := strings.Cut(line, "=")
			cur = &Section{Name: strings.TrimSpace(name)}
		case strings.Contains(line, "="):
			if cur == nil {
				continue
			}
			k, val, _ := strings.Cut(line, "=")
			cur.Set(strings.TrimSpace(k), unquoteValue(val))
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

// unquoteValue reverses quoteValue. VICI quotes any value it would otherwise be
// ambiguous about, so a reply can carry "0.0.0.0/0,::/0" quoted; leaving the
// quotes on would make every parsed value compare against a literal that the
// panel never sent.
func unquoteValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return v
	}
	inner := v[1 : len(v)-1]
	return strings.NewReplacer(`\"`, `"`, `\n`, "\n", `\r`, "\r", `\\`, `\`).Replace(inner)
}

// VICIReachable reports whether a VICI socket can be connected to at all. The
// panel uses this to distinguish "strongSwan is not installed/running" from
// "the configuration was rejected", which are different operator problems.
func VICIReachable(path string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("unix", strings.TrimSpace(path), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}