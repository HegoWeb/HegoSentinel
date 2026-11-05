#!/usr/bin/env sh
# HegoSentinel Per-Run Network Namespace Egress Policy Enforcer (Sprint 1 — P0)
# Executed in the network namespace Setup init container BEFORE dropping capabilities and starting the unprivileged worker.
# Enforces default DROP on OUTPUT/FORWARD and blocks all private, loopback, link-local, metadata, and IPv6 transition ranges.

set -eu

nft flush ruleset

nft -f - <<'EOF'
table inet hegosentinel_egress {
  chain output {
    type filter hook output priority 0; policy drop;

    # Reject invalid packets immediately
    ct state invalid drop

    # Deny IPv4 private, loopback, link-local, cloud metadata, CGNAT, multicast, broadcast
    ip daddr {
      0.0.0.0/8,
      10.0.0.0/8,
      100.64.0.0/10,
      127.0.0.0/8,
      169.254.0.0/16,
      169.254.169.254/32,
      172.16.0.0/12,
      192.0.0.0/24,
      192.0.2.0/24,
      192.168.0.0/16,
      198.18.0.0/15,
      198.51.100.0/24,
      203.0.113.0/24,
      224.0.0.0/4,
      240.0.0.0/4,
      255.255.255.255/32
    } counter drop

    # Deny IPv6 loopback, unspecified, IPv4-mapped, NAT64, Teredo, 6to4, ULA/metadata, link-local, multicast
    ip6 daddr {
      ::/128,
      ::1/128,
      ::ffff:0:0/96,
      64:ff9b::/96,
      100::/64,
      2001::/32,
      2001:2::/48,
      2001:db8::/32,
      2002::/16,
      fc00::/7,
      fd00:ec2::254/128,
      fe80::/10,
      ff00::/8
    } counter drop

    # Allow established return frames only for explicitly approved pinned outbound flows
    ct state established,related accept
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
  }
}
EOF

