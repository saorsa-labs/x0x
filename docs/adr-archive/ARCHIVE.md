# Historical numbered ADRs

David accepted the transfer on 10 Oct 2026. David placed ADR 0115 in A02
and ADR 0116 in A07 on 10 Oct 2026. The bodies of the mapped records live
in this directory. Each `docs/adr/NNNN-*.md` path remains a link to the
same bytes.

The bytes are unchanged. `move.json` records the path, the link, and the
sha256 of each file. A content change of an Accepted ADR still fails
`scripts/adr-governance.py`.

A Proposed record can change in place when David accepts it. The same
commit updates its `move.json` sha256. On 20 Oct 2026 this applied to
ADR 0110 and ADR 0109.

The plan is [the 15 ADR set](../adr/consolidated/README.md).
