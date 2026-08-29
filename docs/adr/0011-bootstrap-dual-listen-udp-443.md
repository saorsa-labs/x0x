# 0011 — Bootstrap nodes dual-listen on UDP/443; clients dial 443 first and never bind privileged ports

- Status: Accepted
- Date: 2026-05-30

## Context

x0x's transport is QUIC over UDP (via `ant-quic`), with bootstrap, relay, and
gossip all on **UDP 5483**. Users behind full-tunnel VPNs (notably Cloudflare
WARP / "1.1.1.1: Faster Internet"), corporate/hotel/captive networks, mobile
carriers, and CGNAT report that x0x cannot connect. Investigation
(see [[ackv2-empty-response-no-retry-2026-05-29]] for the related transport
work, and the WARP support thread) shows two mechanisms:

1. **Port filtering / throttling.** These networks carry UDP/443 (mainstream
   HTTP/3) cleanly but throttle or drop arbitrary high UDP ports like 5483.
2. **MTU.** WireGuard-style tunnels shrink the path MTU; QUIC's mandatory
   1200-byte Initial (`ant-quic` `MIN_INITIAL_SIZE = 1200`) can be dropped,
   so the handshake never completes. The 443 path is usually MTU-tuned because
   it is the VPN's optimized hot path.

A naive reading is "move x0x to UDP/443." The decisive nuance: **for traversal,
what matters is the *destination* port a client dials, not the client's own
*listen* port.** Egress filtering is destination-based; a client behind a
hostile network makes *outbound* connections (ephemeral high source port → no
privilege needed) and, behind WARP/symmetric NAT, cannot receive inbound at all
(it relays — handled by the existing X0X-0070 peer relay + ant-quic MASQUE).

Binding a *listener* on UDP/443 requires privilege (<1024 ⇒ root /
`CAP_NET_BIND_SERVICE` on Linux, root on macOS; Windows excepted). x0x is a
user-run daemon (`~/.x0x`); requiring elevation for every client is a security
and UX regression — and buys nothing, because dialing a low destination port is
unprivileged and inbound is relayed anyway.

## Decision

1. **Each bootstrap / relay VPS is reachable on UDP/443 *and* UDP/5483.**
   Achieved by running **two single-port `x0xd` listeners per host**: a
   dedicated root-run instance bound to `0.0.0.0:443` *and* the original
   instance on `:5483`. Each listener is a normal, unmodified node binding one
   port (its existing dual-stack path already serves both IPv4 and IPv6 on that
   port), so **no ant-quic change is required**.

   > **Implementation note / supersedes the original draft.** This ADR first
   > proposed one node dual-*listening* on both ports via ant-quic's
   > `NatTraversalConfig.additional_bind_addrs`. Investigation (2026-05-30)
   > found that field does **not** bind a second socket — it only *advertises*
   > an additional NAT candidate; a quinn/ant-quic `Endpoint` binds exactly one
   > UDP socket, and a single endpoint cannot reply from the specific local
   > *port* a client dialed (its send path routes only by address family). True
   > single-identity dual-listen would require a new multi-socket transport
   > feature in ant-quic (a per-remote source-socket affinity map) — real work
   > with same-day prod risk. The two-listener model delivers the same user
   > outcome (a bootstrap reachable on 443) with zero transport changes, so it
   > was chosen. Cost: a host presents **two** seed hints / identities instead
   > of one dual-homed identity, and runs one extra `x0xd`. Identity is
   > key-based, so two listeners are simply two entries in the seed list
   > (see [[0001-bootstrap-peers-are-seed-hints-only]]).
2. **Clients never bind a privileged port.** The client listener stays on the
   high port (5483 or ephemeral). `additional_bind_addrs` defaults to empty, so
   client behaviour is unchanged and never needs root.
3. **The bootstrap seed list carries both `IP:443` and `IP:5483`** for each
   node, and the client connect path tries 443 first, falling back to 5483.
   This is what traverses WARP/firewalls/CGNAT (outbound dest = 443).
4. **`x0xd --doctor` / `/diagnostics/connectivity` detect a full-tunnel-VPN /
   constrained-MTU path** (external_addr in a known VPN egress range, low
   `current_mtu` / lost PLPMTUD probes, or `can_receive_direct=false` with
   handshake timeouts) and emit actionable guidance ("full-tunnel VPN detected —
   use split-tunnel / exclude x0x / DNS-only mode"). Turns a silent failure into
   self-service.

## Consequences

- **Pro:** WARP and the broader UDP-hostile-network class (corporate/hotel/
  CGNAT/mobile) can reach the mesh by dialing bootstrap/relay on 443. x0x-on-443
  blends with HTTP/3 at the port level (censorship-resistance bonus). No client
  privilege change.
- **Con / bounded:** MTU is still a hard floor — a path that cannot carry a
  1200-byte datagram cannot run QUIC regardless of port; 443 mitigates
  throttling/DPI and rides a better-tuned path but is not a universal fix. The
  only complete answer for sub-1200-MTU paths is a future TCP/HTTP fallback
  transport (out of scope here).
- **Migration:** each bootstrap host keeps its `:5483` listener *and* adds a
  `:443` listener, so old (5483-only) and new clients both connect; the seed
  list carries both `IP:443` and `IP:5483` per host. Heterogeneous meshes are
  fine — identity is key-based and actual ports propagate via announcements;
  only the seed list has a fixed assumption, and it carries both. Deploy order:
  stand up `:443` listeners and open UDP/443 **before** shipping the client
  release that advertises `:443`, so no client ever dials a dead port.
- **Ops:** open UDP/443 on the bootstrap fleet; ensure nothing else holds
  UDP/443 there (TCP/443 web is independent of UDP/443). Each host gains a
  second service (e.g. `x0xd-443.service`) running as root with its own state
  dir and `bind_address = "[::]:443"`; the existing `:5483` service is
  unchanged. Deploy with `.deployment/deploy-443.sh` (generates the `:443`
  config from the host's live `/etc/x0x/config.toml`, overriding `bind_address`,
  `data_dir`, `machine_key_path`, and `api_address` (→ `12643`, distinct from
  the prod `12600`) so it can't drift and can't collide on the API port).
- **Self-update caveat:** both services exec the same `/opt/x0x/x0xd`, but the
  self-updater only restarts `x0xd.service`. After a binary upgrade the `:443`
  instance keeps running the old image until it is restarted
  (`systemctl restart x0xd-443`) or the host reboots. Re-running
  `deploy-443.sh` restarts it. (A future improvement is to add `x0xd-443` to
  the updater's restart set.)

## Supersedes / relates to

- Relates to [[0001-bootstrap-peers-are-seed-hints-only]] (seed list is hints;
  this adds a second port per hint).
- Builds on the existing X0X-0070 application-level peer relay and ant-quic
  MASQUE relay for the no-inbound-reachability case.
