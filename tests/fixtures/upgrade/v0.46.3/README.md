Public production release fixture, preserved byte for byte from:
https://github.com/saorsa-labs/x0x/releases/download/v0.46.3/

SHA-256:

- `release-manifest.json`: `4770cb72da68f232abc164a7b20035217b99b64ff157faa333dbb729786b84c0`
- `release-manifest.json.sig`: `5927a8f8705ad543155ebe5b301463a5d9ec3941fc6670559c1c2e6c1dbc6aea`

These public bytes exercise both packaged verification probes. Default builds
must accept this production signature; `upgrade-test-signing` builds must reject
it, proving that the fixture key replaces the production trust root.
