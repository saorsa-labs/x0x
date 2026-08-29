# ADR-0011 mechanics — Bootstrap dual-listen on UDP/443

> Extracted 2026-08-29 from the immutable [ADR 0011](../adr/0011-bootstrap-dual-listen-udp-443.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the implementation note and operational caveats relocated verbatim
> so this file is their maintained home — future updates
> belong here, not in the ADR.

## Implementation note (Decision §1 excerpt; heading editorial)

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

---

## Ops caveats (Consequences excerpt; heading editorial)

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
