# Historical numbered ADRs

David accepted the transfer on 10 Oct 2026. The bodies of the 100 records
in the [transfer map](../adr/consolidated/TRANSFER.md) live in this directory.
Each `docs/adr/NNNN-*.md` path remains a link to the same bytes.

The bytes are unchanged. `move.json` records the path, the link, and the
sha256 of each file. A content change of an Accepted ADR still fails
`scripts/adr-governance.py`.

ADR 0115 and ADR 0116 are not in the transfer map. They stay in `docs/adr/`.
The plan does not assign either one a slot.

The plan is [the 15 ADR set](../adr/consolidated/README.md).
