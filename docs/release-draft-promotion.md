# Release draft promotion checklist

The release workflow creates a **draft**. Publishing that draft exposes its
signed manifest through GitHub's latest-release API and may start fleet
auto-update within minutes. Never publish it as a way to obtain test bytes.

For the tagged workflow run:

1. Confirm every required workflow job succeeded and retain the run ID, tag
   commit, tag tree, and `release-custody.json`.
2. Download the draft's `x0x-linux-x64-gnu.tar.gz`, checksum, ML-DSA signature,
   GPG signature, public key, and signed release manifest without publishing the
   draft. Verify both signatures and the archive checksum.
3. Extract `Cargo.lock`, `build-provenance.json`, `x0xd`, and `x0x`. Require the
   provenance source HEAD/tree and lock SHA to equal `release-custody.json`, and
   recompute both binary hashes from the extracted files.
4. Deploy that exact extracted `x0xd` to the isolated testnet without rebuilding.
   Record the local SHA, uploaded temporary-file SHA, installed-file SHA, and
   running executable SHA for every node. All must equal the provenance hash.
5. Run the required E2E suite against those processes. Retain native exits,
   source/lock/binary custody, node identities, process start/uptime, and cleanup
   receipts. Any missing, stale, or mismatched receipt blocks promotion.
6. Re-download the still-draft archive and recompute its hash. It must equal the
   tested archive hash and the signed manifest entry. Confirm every draft asset
   is unchanged from the successful workflow output.
7. Explicitly promote that existing draft through an authenticated operator or
   agent session. Do not rebuild, replace assets, move the tag, or create a
   second release. Confirm that the `Publish promoted release` workflow starts,
   then immediately verify the public assets and running fleet hashes against
   the retained custody record. GitHub suppresses most workflow events caused by
   `GITHUB_TOKEN`, so an Actions job using that token must not perform promotion:
   [triggering a workflow from a workflow](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).
8. The GitHub [`release: published` event](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#release)
   automatically resumes the preserved crates.io and ClawHub publication jobs
   after promotion. Require that workflow to finish successfully; the jobs are
   absent from draft creation only so they cannot expose the candidate early.

If any asset changes, discard the draft and repeat the complete build, signing,
testnet, and custody sequence. A version string or health response is not a
binary identity check.
