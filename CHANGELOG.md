# Changelog

## [Unreleased]


### Fixed
- OpenVPN: removed invalid config directives, added `username-as-common-name`, switched to mgmt pw-file + generated verify script (script-security 2), proper tls-server/dh handling, and directive allow-list enforcement.
- IKEv2: hardened config handling and validation.

### Added
- OpenVPN/IKEv2: inbound (server) and outbound (exit) support with per-client auth, session listing/disconnect, live status, traffic accounting, and probe integration.
- E2E Docker harness for real openvpn/strongswan validation.
- Directive allow-list tests for OpenVPN configs.

### Changed
- Revocation/disconnect paths improved for VPN inbounds (batch removals now apply VPN runtime changes).
