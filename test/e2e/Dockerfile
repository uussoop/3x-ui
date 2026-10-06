# E2E sandbox for the VPN adapters.
#
# The fakes in internal/openvpn and internal/ikev2 never parse a generated
# config and never speak a real management/VICI protocol, so a directive the
# daemon does not understand reaches production unnoticed. This image carries
# the real daemons so the same renderers can be driven against them; it runs as
# root with NET_ADMIN because creating a tun device is exactly what the panel
# has to be able to do.
#
# Build from the repository root:
#   docker build -f test/e2e/Dockerfile -t 3x-ui-e2e .
# Run the suite against the working tree (no rebuild needed after edits):
#   docker run --rm --cap-add=NET_ADMIN --volume "$PWD":/src -w /src 3x-ui-e2e
FROM golang:1.27-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        openvpn \
        strongswan \
        strongswan-charon \
        strongswan-swanctl \
        strongswan-pki \
        libcharon-extauth-plugins \
        libcharon-extra-plugins \
        libstrongswan-extra-plugins \
        libstrongswan-standard-plugins \
        iptables \
        iproute2 \
        openssl \
        easy-rsa \
        procps \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Refuse to ship an image that cannot exercise the feature under test: the
# EAP-MSCHAPv2 server plugin is what authenticates IKEv2 clients, and it lives
# in a separate Debian package that is easy to forget.
RUN test -f /usr/lib/ipsec/plugins/libstrongswan-eap-mschapv2.so \
    && command -v openvpn >/dev/null \
    && command -v swanctl >/dev/null \
    && test -x /usr/lib/ipsec/charon

# Fetch the toolchain and modules while building so a test run never needs the
# network. The repo itself is bind-mounted at run time.
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

CMD ["go", "test", "-tags", "e2e", "-count=1", "./internal/openvpn/...", "./internal/ikev2/..."]
