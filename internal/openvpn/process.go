package openvpn

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

var (
	gracefulStopTimeout = 5 * time.Second
	forceStopTimeout    = 2 * time.Second
)

// procLogWriter consumes the openvpn child's stdout/stderr, forwarding each
// line to the panel log so the operator can see why a tunnel refused to come
// up, and remembering the most recent line for diagnostics.
//
// OpenVPN logs credentials in some failure modes (a rejected auth-user-pass
// line, a management auth failure), so every line is scrubbed before it is
// written to the panel log or kept as the "last line" — a tunnel that cannot
// connect must not turn the log viewer into a credential store.
type procLogWriter struct {
	mu       sync.Mutex
	label    string
	buf      string
	lastLine string
}

func (w *procLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf += string(p)
	for {
		i := strings.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := w.buf[:i]
		w.buf = w.buf[i+1:]
		w.emitLocked(line)
	}
	return len(p), nil
}

// Flush emits any buffered partial line so a final un-terminated error is not
// lost when the process exits.
func (w *procLogWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf != "" {
		line := w.buf
		w.buf = ""
		w.emitLocked(line)
	}
}

func (w *procLogWriter) emitLocked(line string) {
	trimmed := strings.TrimSpace(strings.TrimRight(line, "\r"))
	if trimmed == "" {
		return
	}
	trimmed = ScrubLine(trimmed)
	w.lastLine = trimmed
	logger.Infof("openvpn: %s | %s", w.label, trimmed)
}

func (w *procLogWriter) LastLine() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastLine
}

// tunnelProcess is the lifecycle of one openvpn child process.
//
// It is an interface rather than a concrete *Process so the manager's recovery
// paths — rollback after a rejected change, backoff after a failed start,
// per-tunnel isolation — can be exercised on a machine with no openvpn binary,
// no TUN device and no root. Those paths are exactly the ones that must not be
// wrong, and "we could not test it" is not a reason to leave them untested.
type tunnelProcess interface {
	Start() error
	Stop() error
	IsRunning() bool
	LastLine() string
}

// spawnProcess creates the child process for one tunnel. Production always uses
// the real openvpn child; tests substitute a fake through this variable.
var spawnProcess = func(configPath, label string) tunnelProcess {
	return newProcess(configPath, label)
}

// Process wraps a single openvpn invocation for one tunnel.
type Process struct {
	mu              sync.RWMutex
	cmd             *exec.Cmd
	done            chan struct{}
	configPath      string
	logWriter       *procLogWriter
	exitErr         error
	intentionalStop atomic.Bool
}

func newProcess(configPath, label string) *Process {
	return &Process{configPath: configPath, logWriter: &procLogWriter{label: label}}
}

var _ tunnelProcess = (*Process)(nil)

// IsRunning reports whether the openvpn process is currently running.
func (p *Process) IsRunning() bool {
	p.mu.RLock()
	cmd, done := p.cmd, p.done
	p.mu.RUnlock()
	if cmd == nil || cmd.Process == nil {
		return false
	}
	if done != nil {
		select {
		case <-done:
			return false
		default:
		}
	}
	return true
}

// LastLine returns the most recent scrubbed log line.
func (p *Process) LastLine() string { return p.logWriter.LastLine() }

// Start launches openvpn against its generated config. Passing a cancelled
// context is not supported on purpose: the tunnel's lifetime belongs to the
// panel, not to whichever request happened to start it.
func (p *Process) Start() error {
	if p.IsRunning() {
		return errors.New("openvpn is already running")
	}
	if !BinaryAvailable() {
		return fmt.Errorf("openvpn binary not found at %s", GetBinaryPath())
	}
	// --daemon is deliberately not used: the panel owns the process tree so it
	// can stop the tunnel deterministically and reap it on exit.
	cmd := exec.Command(GetBinaryPath(), "--config", p.configPath)
	cmd.Stdout = p.logWriter
	cmd.Stderr = p.logWriter
	done := make(chan struct{})
	p.mu.Lock()
	p.cmd = cmd
	p.done = done
	p.exitErr = nil
	p.mu.Unlock()
	p.intentionalStop.Store(false)
	if err := cmd.Start(); err != nil {
		close(done)
		p.mu.Lock()
		p.cmd = nil
		p.mu.Unlock()
		return err
	}
	go p.wait(cmd, done)
	return nil
}

func (p *Process) wait(cmd *exec.Cmd, done chan struct{}) {
	defer close(done)
	err := cmd.Wait()
	p.logWriter.Flush()
	if err == nil || p.intentionalStop.Load() {
		return
	}
	logger.Errorf("openvpn: process exited: %v", err)
	p.mu.Lock()
	p.exitErr = err
	p.mu.Unlock()
}

// Stop terminates the tunnel, preferring a graceful signal so openvpn can tear
// its TUN device down cleanly, and falling back to a kill if it will not exit.
func (p *Process) Stop() error {
	if !p.IsRunning() {
		return errors.New("openvpn is not running")
	}
	p.intentionalStop.Store(true)
	p.mu.RLock()
	cmd, done := p.cmd, p.done
	p.mu.RUnlock()
	if cmd == nil || cmd.Process == nil {
		return errors.New("openvpn is not running")
	}

	if runtime.GOOS == "windows" {
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		return waitForExit(done, forceStopTimeout)
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			return waitForExit(done, forceStopTimeout)
		}
		return err
	}
	if err := waitForExit(done, gracefulStopTimeout); err == nil {
		return nil
	}
	logger.Warning("openvpn: did not stop after SIGTERM, killing process")
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return waitForExit(done, forceStopTimeout)
}

func waitForExit(done <-chan struct{}, timeout time.Duration) error {
	if done == nil {
		return nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return fmt.Errorf("timed out waiting for openvpn to stop after %s", timeout)
	}
}

