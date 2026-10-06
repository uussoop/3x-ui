package ikev2

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// RenderConnection builds the VICI `load-conn` payload for an instance's
// connection.
//
// Secrets are passed to charon in the message and never written to disk where
// they can be avoided: an account password and a private key sitting in a config
// file outlive the process, and the panel already keeps the authoritative copy in
// its own storage. The generated connection carries the panel's account as the
// IKE identity so a child's SA is attributable back to it.
func RenderConnection(inst Instance) []Section {
	name := inst.instanceName()
	conn := Section{Name: "connections." + name}
	conn.Set("version", strconv.Itoa(ikeVersion(inst)))
	conn.Set("proposals", nonEmpty(inst.Encryption, "aes256-sha256-modp2048"))
	if inst.isServer() {
		conn.Set("local_addrs", nonEmpty(inst.Listen, "0.0.0.0"))
		conn.Set("local_port", strconv.Itoa(orDefault(inst.Port, 500)))
		// A responder must accept initiation; an initiator must not. Setting the
		// wrong one here is not a style issue: it either never answers or starts
		// dialling a peer it is supposed to serve.
		conn.Set("mode", "passive")
	} else {
		conn.Set("remote_addrs", inst.Remote)
		conn.Set("remote_port", strconv.Itoa(orDefault(inst.RemotePort, 500)))
		if strings.TrimSpace(inst.LocalAddr) != "" {
			conn.Set("local_addrs", inst.LocalAddr)
		}
		if inst.LocalPort > 0 {
			conn.Set("local_port", strconv.Itoa(inst.LocalPort))
		}
		conn.Set("mode", "active")
		conn.Set("mobike", "no")
		if inst.NATTraversal {
			conn.Set("encap", "yes")
		}
	}
	// Each exit gets its own reqid and identity. Sharing either would let two
	// exits collide in kernel XFRM state, so tearing one down could tear down
	// policies the other still needs.
	if !inst.isServer() {
		conn.Set("reqid", strconv.Itoa(reqID(inst)))
		conn.Set("mark", "-1")
	}
	conn.Set("rekey_time", "4h")
	conn.Set("over_time", "3m")
	// Bounded DPD: a dead path must be detected and torn down rather than left as
	// a half-open SA that still looks connected.
	conn.Set("dpd_delay", "30s")
	conn.Set("dpd_timeout", "120s")
	return []Section{conn}
}

// childSAConfig builds the `child-sa` definition for an instance.
//
// For a responder this is the pool it offers and the DNS it pushes; for an
// initiator it is the protected subnet it wants to send through the tunnel. A
// rejected child config is where traffic would otherwise bypass policy, so the
// responder offers only the configured pool and the exit installs policies for
// all traffic.
func childSAConfig(inst Instance) []Section {
	name := inst.instanceName()
	cfg := Section{Name: "children." + name}
	if inst.isServer() {
		if inst.Subnet != "" {
			cfg.Set("local_addrs", inst.Subnet)
			cfg.Set("remote_addrs", "%dynamic")
		}
		if inst.DNSServer != "" {
			cfg.Set("dns", "1")
			cfg.Set("right_dns_hosts", inst.DNSServer)
		}
		// A responder installs nothing on its own; a child's policies follow the
		// configuration the client asked for.
		cfg.Set("start_action", "none")
		cfg.Set("mode", "tunnel")
	} else {
		// An exit sends everything through the tunnel; without these the child's
		// SA would cover nothing and traffic would leave the real interface.
		cfg.Set("local_addrs", "0.0.0.0/0,::/0")
		cfg.Set("remote_addrs", "0.0.0.0/0,::/0")
		cfg.Set("start_action", "start")
		cfg.Set("mode", "tunnel")
	}
	cfg.Set("esp_proposals", nonEmpty(inst.Encryption, "aes256-sha256-modp2048"))
	cfg.Set("rekey_time", "1h")
	cfg.Set("df", "on")
	cfg.Set("mark", "-1")
	// The kernel interface is named explicitly. charon's default is
	// ipsec0/ipsec1..., which is not something the panel can bind Xray's exit
	// outbound to by name — and two exits must never land on one interface.
	dev := inst.devName()
	cfg.Set("if_name_in", dev)
	cfg.Set("if_name_out", dev)
	// Separate XFRM policy identities per exit, so two exits never share policy.
	if !inst.isServer() {
		cfg.Set("reqid", strconv.Itoa(reqID(inst)))
	}
	return []Section{cfg}
}

// RenderAuth builds the authentication definitions for an instance.
//
// EAP-MSCHAPv2 with the panel account as the IKE identity is the default: it
// keeps the tunnel's access control in the panel's own client store, so
// disabling or expiring an account there actually cuts tunnel access. A
// pre-shared key is only configured for the auth method that actually needs one —
// configuring both at once would let a client that presents a PSK skip the
// password check the panel is relying on for accounting.
func RenderAuth(inst Instance) []Section {
	var out []Section
	name := inst.instanceName()
	method := inst.authMethod()

	if inst.isServer() {
		for _, c := range inst.Clients {
			if !c.Enabled {
				continue
			}
			local := Section{Name: fmt.Sprintf("connections.%s.local-%s", name, authKey(c))}
			// An empty id matches any peer identity; the constraint that decides
			// who is allowed in is the account list below, not this section.
			local.Set("id", "%any")
			local.Set("auth", "eap")
			local.Set("eap_identity", "*")
			out = append(out, local)

			// The IKE identity is the account's own id, so a child's SA carries it
			// back and the panel can attribute the session and its bytes.
			remote := Section{Name: fmt.Sprintf("connections.%s.remote-%s", name, authKey(c))}
			remote.Set("id", c.ID)
			remote.Set("auth", "eap-mschapv2")
			remote.Set("eap_identity", "*")
			remote.Set("send_id", "no")
			out = append(out, remote)
		}
		if method == "cert" && inst.CA != "" {
			ts := Section{Name: "connections." + name + ".remote-ca"}
			ts.Set("id", "%any")
			ts.Set("auth", "pubkey")
			ts.Set("ca", caFileFor(inst))
			ts.Set("remote_addrs", "%dynamic")
			out = append(out, ts)
		}
		if method == "psk" && inst.PSK != "" {
			// The PSK is sent inline. strongSwan accepts it in the message, and
			// keeping it out of the on-disk config means a leaked config file does
			// not hand over tunnel access.
			ts := Section{Name: "connections." + name + ".remote-any"}
			ts.Set("id", "%any")
			ts.Set("auth", "psk")
			ts.Set("psk", inst.PSK)
			out = append(out, ts)
		}
		return out
	}

	local := Section{Name: "connections." + name + ".local"}
	local.Set("id", clientLocalID(inst))
	local.Set("auth", "eap")
	local.Set("send_id", "yes")
	out = append(out, local)

	remote := Section{Name: "connections." + name + ".remote"}
	remote.Set("id", nonEmpty(inst.RemoteID, inst.Remote))
	switch method {
	case "psk":
		remote.Set("auth", "psk")
		remote.Set("psk", nonEmpty(inst.PSK, inst.Password))
	case "cert":
		if inst.ClientCert != "" {
			cert := Section{Name: "certificates." + name}
			cert.Set("crt", inst.ClientCert)
			out = append(out, cert)
		}
		if inst.ClientKey != "" {
			key := Section{Name: "private." + name}
			key.Set("key", inst.ClientKey)
			out = append(out, key)
		}
		remote.Set("auth", "pubkey")
	default:
		remote.Set("auth", "eap-mschapv2")
		remote.Set("eap_identity", inst.Username)
	}
	return append(out, remote)
}

// RenderHostIdentity loads the panel's own host certificate and key, which is
// what a client verifies when it pins the panel's CA, and what a client
// certificate authenticator needs on the responder side.
func RenderHostIdentity(inst Instance) []Section {
	if strings.TrimSpace(inst.HostCert) == "" {
		return nil
	}
	cert := Section{Name: "certificates.host-" + inst.instanceName()}
	cert.Set("crt", inst.HostCert)
	out := []Section{cert}
	if strings.TrimSpace(inst.HostKey) != "" {
		key := Section{Name: "private.host-" + inst.instanceName()}
		key.Set("key", inst.HostKey)
		out = append(out, key)
	}
	return out
}

// caFileFor is the 0600 file the CA was written to by writeSecretFiles.
func caFileFor(inst Instance) string {
	return stateDir() + "/" + inst.instanceName() + "/ca.pem"
}

func ikeVersion(inst Instance) int {
	if inst.IKEVersion == 1 || inst.IKEVersion == 2 {
		return inst.IKEVersion
	}
	return 2
}

func reqID(inst Instance) int {
	if inst.ReqID > 0 {
		return inst.ReqID
	}
	return reqIDFor(inst.ID)
}

func clientLocalID(inst Instance) string {
	if strings.TrimSpace(inst.Identity) != "" {
		return inst.Identity
	}
	return clientIdentity(inst.ID)
}

// authKey makes a connection subsection name from an account. A raw email would
// work in VICI, but sanitising keeps the name predictable for unload/terminate
// lookups and avoids surprises if an address contains characters strongSwan
// treats specially in a section name.
func authKey(c ClientConfig) string {
	var b strings.Builder
	for _, r := range c.Username {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '-' || r == '_' || r == '@':
			b.WriteRune('-')
		default:
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "acct"
	}
	return b.String()
}

// fingerprint digests everything a connection depends on, so a reconcile can
// tell "unchanged" from "reload needed" without diffing rendered payloads.
// Credentials are hashed, so the value is safe to compare and log.
func (inst Instance) fingerprint() string {
	h := sha256.New()
	f := func(k, v string) { fmt.Fprintf(h, "%s=%s\x00", k, v) }
	f("role", string(inst.role()))
	f("listen", inst.Listen)
	f("port", strconv.Itoa(inst.Port))
	f("remote", inst.Remote)
	f("remoteID", inst.RemoteID)
	f("remotePort", strconv.Itoa(inst.RemotePort))
	f("localAddr", inst.LocalAddr)
	f("localPort", strconv.Itoa(inst.LocalPort))
	f("nat", strconv.FormatBool(inst.NATTraversal))
	f("ike", strconv.Itoa(ikeVersion(inst)))
	f("enc", inst.Encryption)
	f("subnet", inst.Subnet)
	f("dns", inst.DNSServer)
	f("hostCert", digest(inst.HostCert))
	f("hostKey", digest(inst.HostKey))
	f("ca", digest(inst.CA))
	f("psk", digest(inst.PSK))
	f("method", inst.authMethod())
	f("uniqueIds", strconv.FormatBool(inst.UniqueIDs))
	f("identity", inst.Identity)
	f("reqid", strconv.Itoa(reqID(inst)))
	f("user", digest(inst.Username))
	f("pass", digest(inst.Password))
	f("clientCert", digest(inst.ClientCert))
	f("clientKey", digest(inst.ClientKey))
	f("routeXray", strconv.FormatBool(inst.RouteThroughXray))
	f("xrayPort", strconv.Itoa(inst.XrayRoutePort))
	lines := make([]string, 0, len(inst.Clients))
	for _, c := range inst.Clients {
		if !c.Enabled {
			continue
		}
		lines = append(lines, c.Username+"|"+c.ID+"|"+digest(c.Password))
	}
	sort.Strings(lines)
	f("clients", strings.Join(lines, ";"))
	return hex.EncodeToString(h.Sum(nil))
}

func digest(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func nonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return strings.TrimSpace(v)
}

func orDefault(v, fallback int) int {
	if v == 0 {
		return fallback
	}
	return v
}