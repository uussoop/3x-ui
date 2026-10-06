package openvpn

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// mgmtClient is a client for OpenVPN's management interface — the only
// supported way to observe and control a running daemon without restarting it.
// The protocol is line based over TCP: the server greets, then answers each
// command either with a single line or with a block terminated by "END".
//
// A connection is short-lived by design. The panel polls status on an interval;
// holding a long-lived connection would make a restarted daemon look like a
// hung one and would leave an authenticated session open on a process the panel
// no longer manages.
type mgmtClient struct {
	addr     string
	password string
	timeout  time.Duration
}

// statusReply is the parsed form of a `status 2` reply.
type statusReply struct {
	// Title is the "OpenVPN Client: ..." summary line.
	Title string
	// UpTime is the daemon's reported uptime string, kept for logging only.
	UpTime string
	// Sessions are the live client sessions from ROUTING_TABLE.
	Sessions []mgmtSession
	// UpBytes/DownBytes are the global TUN counters from STATISTICS.
	UpBytes   int64
	DownBytes int64
	// HasCounters reports whether a STATISTICS section was present. Its
	// absence is not an error — older daemons and some states omit it — but it
	// must not be mistaken for zero traffic.
	HasCounters bool
}

type mgmtSession struct {
	// CommonName is the authenticated username openvpn assigned to the client.
	CommonName string
	// VirtualIP/VirtualIPv6 are the in-tunnel addresses.
	VirtualIP   string
	VirtualIPv6 string
	// RealAddress is "host:port" of the client's pre-tunnel endpoint. It is
	// what client-kill needs.
	RealAddress string
	// BytesIn/BytesOut are this session's own counters (status 2), -1 when the
	// daemon did not report them.
	BytesIn  int64
	BytesOut int64
	// Since is the raw timestamp string.
	Since string
}

// open dials the management interface and completes the password handshake.
func (c *mgmtClient) open() (*mgmtConn, error) {
	if c.password == "" {
		// Refusing to connect without a password rather than trying: an
		// unauthenticated management interface is a local privilege problem,
		// and silently proceeding would hide a misconfiguration.
		return nil, errors.New("openvpn management password is not set")
	}
	d := net.Dialer{Timeout: c.timeout}
	conn, err := d.Dial("tcp", c.addr)
	if err != nil {
		return nil, err
	}
	if c.timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(c.timeout))
	}
	mc := &mgmtConn{
		conn:     conn,
		r:        bufio.NewReader(conn),
		w:        bufio.NewWriter(conn),
		deadline: c.timeout,
	}
	// The daemon greets with an informational line before accepting commands.
	if _, _, err := mc.read(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("openvpn management greeting: %w", err)
	}
	if err := mc.send(c.password); err != nil {
		_ = conn.Close()
		return nil, err
	}
	// After the password the daemon acknowledges, may emit async status lines,
	// and only then prints its prompt. The prompt is the barrier: it is the
	// point at which the daemon is ready for a command.
	if err := mc.drainUntilPrompt(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return mc, nil
}

type mgmtConn struct {
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
	// deadline bounds the whole connection lifetime; it is re-applied after
	// each peek so one slow read cannot extend an exchange indefinitely.
	deadline time.Duration
}

func (m *mgmtConn) Close() error { return m.conn.Close() }

func (m *mgmtConn) send(line string) error {
	if _, err := m.w.WriteString(line + "\n"); err != nil {
		return err
	}
	return m.w.Flush()
}

// promptPeekTimeout bounds how long read waits for a byte after seeing what
// looks like a prompt. The daemon sends its prompt immediately before it waits
// for a command, so anything still buffered belongs to the same token; a quiet
// reader therefore means the token really did end there.
const promptPeekTimeout = 250 * time.Millisecond

// read returns the next protocol token.
//
// OpenVPN's prompt is written without a trailing newline, so treating it as an
// ordinary line would block until the connection deadline and every status poll
// would fail. Bytes are read one at a time, and once the buffer holds only the
// prompt the reader peeks (without consuming) to see whether more of the same
// token follows. That is what distinguishes a real prompt from the leading '>'
// of a '>INFO:' line, which would otherwise be mistaken for one.
//
// The second return value reports whether the token was the prompt.
func (m *mgmtConn) read() (string, bool, error) {
	var buf []byte
	for {
		b, err := m.r.ReadByte()
		if err != nil {
			return "", false, err
		}
		if b == '\n' {
			return strings.TrimRight(string(buf), "\r"), false, nil
		}
		buf = append(buf, b)
		if strings.TrimSpace(string(buf)) != ">" {
			continue
		}
		// The buffer is only the prompt so far. Peek decides whether this
		// token ends here or continues as an informational line.
		more, err := m.peekReadable(promptPeekTimeout)
		if err != nil || !more {
			return ">", true, nil
		}
	}
}

// peekReadable reports whether at least one more byte is available within d,
// consuming nothing. The connection deadline is restored afterwards so the
// caller's overall timeout still governs the whole exchange.
func (m *mgmtConn) peekReadable(d time.Duration) (bool, error) {
	if m.r.Buffered() > 0 {
		return true, nil
	}
	if err := m.conn.SetReadDeadline(time.Now().Add(d)); err != nil {
		return false, err
	}
	defer func() {
		_ = m.conn.SetReadDeadline(time.Now().Add(m.deadline))
	}()
	_, err := m.r.Peek(1)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// drainUntilPrompt consumes the daemon's post-auth banner and any async lines
// until the prompt arrives. An error line here means authentication was
// rejected, and is surfaced rather than swallowed.
func (m *mgmtConn) drainUntilPrompt() error {
	for {
		line, prompt, err := m.read()
		if err != nil {
			return err
		}
		if isMgmtError(line) {
			return fmt.Errorf("openvpn management auth failed: %s", strings.TrimSpace(line))
		}
		if prompt {
			return nil
		}
	}
}

// command runs a single-line command and returns its response line.
func (m *mgmtConn) command(line string) (string, error) {
	if err := m.send(line); err != nil {
		return "", err
	}
	resp, _, err := m.read()
	if err != nil {
		return "", err
	}
	return resp, nil
}

// block runs a command whose reply is an "END"-terminated block and returns its
// lines without the terminator.
func (m *mgmtConn) block(line string) ([]string, error) {
	if err := m.send(line); err != nil {
		return nil, err
	}
	var out []string
	for {
		l, _, err := m.read()
		if err != nil {
			return nil, err
		}
		if l == "END" {
			return out, nil
		}
		if isMgmtError(l) {
			return nil, fmt.Errorf("openvpn management: %s", strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(l, ">"), "ERROR")))
		}
		out = append(out, l)
	}
}

// Status fetches and parses the daemon's status block.
func (c *mgmtClient) Status() (statusReply, error) {
	var reply statusReply
	mc, err := c.open()
	if err != nil {
		return reply, err
	}
	defer mc.Close()
	// "status 2" adds ROUTING_TABLE and per-session counters; a daemon too old
	// for it rejects the version, and "status" still yields a usable title.
	lines, err := mc.block("status 2")
	if err != nil {
		lines, err = mc.block("status")
		if err != nil {
			return reply, err
		}
	}
	return parseStatusReply(lines), nil
}

// KillSession disconnects one client by its pre-tunnel address. It is how a
// revoked account is evicted without restarting the tunnel, so every other
// client keeps its session.
func (c *mgmtClient) KillSession(realAddress string) error {
	realAddress = strings.TrimSpace(realAddress)
	if realAddress == "" {
		return errors.New("client-kill needs the client's real address")
	}
	mc, err := c.open()
	if err != nil {
		return err
	}
	defer mc.Close()
	resp, err := mc.command("client-kill " + realAddress)
	if err != nil {
		return err
	}
	if isMgmtError(resp) {
		return fmt.Errorf("client-kill %s: %s", realAddress, strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(resp, ">"), "ERROR")))
	}
	return nil
}

// Signal sends a signal to the daemon (SIGTERM on restart/reload paths).
func (c *mgmtClient) Signal(name string) error {
	mc, err := c.open()
	if err != nil {
		return err
	}
	defer mc.Close()
	resp, err := mc.command("signal " + name)
	if err != nil {
		return err
	}
	if isMgmtError(resp) {
		return fmt.Errorf("signal %s: %s", name, resp)
	}
	return nil
}

func isMgmtError(line string) bool {
	return strings.HasPrefix(line, ">ERROR") || strings.HasPrefix(line, "ERROR")
}

// parseStatusReply turns the raw management status lines into structured data.
// Unrecognised lines are ignored rather than fatal: the format has grown across
// OpenVPN releases and a panel that refuses to report status because of an extra
// informational line would lose visibility into a working tunnel.
func parseStatusReply(lines []string) statusReply {
	var r statusReply
	section := ""
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if !strings.Contains(line, ",") {
			// A section header has no comma; anything else without one is the
			// title or an informational line.
			switch {
			case strings.HasPrefix(line, "ROUTING_TABLE"), strings.HasPrefix(line, "GLOBAL_STATS"),
				strings.HasPrefix(line, "CLIENT_LIST"), strings.HasPrefix(line, "STATISTICS"):
				section = strings.Fields(line)[0]
			default:
				if r.Title == "" {
					r.Title = line
				} else if strings.HasPrefix(line, "Updated") && r.UpTime == "" {
					r.UpTime = line
				}
			}
			continue
		}
		fields := strings.Split(line, ",")
		key := strings.TrimSpace(fields[0])
		// STATISTICS rows repeat the section name in the first column:
		// "STATISTICS,TUN/TAP read bytes,5000".
		if key == "STATISTICS" && len(fields) >= 3 {
			fields = fields[1:]
			key = strings.TrimSpace(fields[0])
		}
		switch key {
		case "ROUTING_TABLE":
			// ROUTING_TABLE,virtual_ip,virtual_ipv6,common_name,real_address,
			//        virtual_address,since[,bytes_received,bytes_sent]
			if len(fields) < 7 {
				continue
			}
			s := mgmtSession{
				VirtualIP:   strings.TrimSpace(fields[1]),
				VirtualIPv6: strings.TrimSpace(fields[2]),
				CommonName:  strings.TrimSpace(fields[3]),
				RealAddress: strings.TrimSpace(fields[4]),
				Since:       strings.TrimSpace(fields[6]),
				BytesIn:     -1,
				BytesOut:    -1,
			}
			if len(fields) > 7 {
				s.BytesIn = parseCounter(fields[7])
				s.BytesOut = parseCounter(fields[8])
			}
			r.Sessions = append(r.Sessions, s)
		case "TUN/TAP read bytes":
			r.DownBytes = parseCounter(fields[1])
			r.HasCounters = true
		case "TUN/TAP write bytes":
			r.UpBytes = parseCounter(fields[1])
			r.HasCounters = true
		case "OpenVPN Client":
			r.Title = strings.TrimSpace(strings.TrimPrefix(line, "OpenVPN Client:"))
		}
		_ = section
	}
	return r
}

// parseCounter reads a byte counter, returning -1 for an absent or malformed
// value. Zero is a legitimate reading and is preserved; -1 means "unknown", so
// a daemon that stopped reporting counters is not read as having sent none.
func parseCounter(s string) int64 {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || v < 0 {
		return -1
	}
	return v
}