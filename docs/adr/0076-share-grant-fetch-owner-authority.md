# ADR-0076: ShareGrant fetch authority — owner installs serve and answer (amending ADR-0070 §2)

- Status: Proposed
- Target: R20 (#967 / #926; not gating R19)
- Amends: [ADR-0070](0070-owner-trust-and-share-grants.md) §2 (the "grantee also attaches the grant grant_id when opening a DM/stream so a daemon that missed delivery can request it" clause and its grantee-served reading)

## Context

ADR-0070 §2 distributes a ShareGrant by DM to the grantee's agents and the shared agents' daemons, and says the grantee "attaches the grant grant_id when opening a DM/stream so a daemon that missed delivery can request it". Read with §2's handler prose, the natural reading is that ANY holder — including the grantee — may answer such a request.

That reading has a hole the missed-delivery case cannot tolerate. A shared agent's daemon that was offline through a grant's **revocation** missed the v3 revocation record for the same reason it missed the grant. If the (revoked) grantee can still push the owner-signed grant bytes — by answering a fetch, or by sending them directly on the fetch-response prefix — the daemon verifies the signature against its own owner (valid), finds no local revocation, stores, and enforces: the revoked grantee has resurrected its access until the hourly-ish v3 republish converges.

## Decision

1. **Owner installs are the only fetch authority.** A daemon serves a grant fetch only when it is an owner install of the grant's signer (`local_owner == grant.owner`, i.e. the store classifies the grant as `Issued`). A grantee-held (Received) grant is never served.
2. **Fetches target owner installs, never the hinter.** When a hint frame names grant ids a daemon does not hold, its fetch requests go to its own owner-trusted peers (owner installs of its owner user) — the revocation source — not to whichever peer sent the hint.
3. **The requester binds and checks the responder.** The in-flight fetch window is keyed by `(grant_id, responder)`, and a fetch response is accepted only when its sender is owner-trusted by this daemon for the grant's owner. Bytes from any other sender are refused without storage, regardless of their signature validity, expiry, or the local revocation set's contents.
4. **The attachment carrier is a typed frame.** The grantee-side "attaches when opening" is a `x0x-sharegrant-hint-v1` frame sent (spawned, never blocking the DM) after a successful user DM on REST `/direct/send` or the WebSocket DM path; the shared daemon accepts at most one hint frame per sender per 30 s window, only from a known contact or owner-trusted peer, and fans its (≤32) ids out as bounded-concurrency fetch requests to an owner install.
5. **Revocation window guarantee.** With (1)–(3), the offline-through-revocation window shrinks from "until v3 gossip converges with the hostile grantee" to "the owner's own v3 propagation between its installs" — the same bound that already governs every other owner-trust decision.

## Consequences

- A grantee cannot use hints, fetches, or the response prefix to move grant bytes; it can still send a `x0x-sharegrant-v1` DM, which the receiving store classifies (`Issued` only when the receiver is an owner install of the signer) and the acceptance gates of §2 already govern.
- Mixed fleets: pre-ADR-0076 daemons that ask a grantee directly get a refusal (Err, ACK withheld) and retry against an owner install; the hint frame is ignored by daemons without the route (delivered as an unknown typed prefix is not possible: it is a registered route only on ADR-0076 daemons).
- ADR-0070 §2's clause keeps its text; this ADR changes only WHO may serve and answer the fetch it describes.

## Open questions (for acceptance)

- Should `MemberAdded`/JoinResult certificate sidecars (#970) be extended to carry grant ids, removing the hint frame entirely? (Deferred; the two mechanisms are independent.)
