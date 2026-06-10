# Network targeting for tests/ scripts

**Default = TESTNET. Production requires explicit `--network prod`.**

All test scripts that talk to the VPS fleet route through a single network
selector so the wrong network can never be hit by accident.

## Quick reference

| Want to… | Run |
|---|---|
| Deploy + verify on **testnet** (default) | `bash tests/e2e_deploy.sh` |
| Deploy + verify on **prod** (5s Ctrl-C window) | `bash tests/e2e_deploy.sh --network prod` |
| Run launch-readiness on testnet | `python3 tests/launch_readiness.py --anchor nyc` |
| Run launch-readiness on prod | `python3 tests/launch_readiness.py --network prod --anchor nyc` |
| 4h soak on testnet | `python3 tests/launch_soak.py --duration-hours 4 --interval-mins 15 --anchor nyc --gate broad-launch` |
| 4h soak on prod | `python3 tests/launch_soak.py --network prod --duration-hours 4 --interval-mins 15 --anchor nyc --gate broad-launch` |

## Architecture

Two fleets share the same 6 VPS hosts (nyc / sfo / helsinki / nuremberg /
singapore / sydney); only ports + services + data dirs differ:

| | TESTNET (default) | PROD |
|---|---|---|
| Bootstrap (UDP) | **6483** | **5483** |
| API (TCP, localhost) | **13600** | **12600** |
| systemd unit | `x0xd-testnet.service` | `x0xd.service` |
| Binary path | `/opt/x0x/x0xd-testnet` | `/opt/x0x/x0xd` |
| Data dir | `/root/.local/share/x0x-testnet/` | `/root/.local/share/x0x/` |
| Config | `/etc/x0x/config-testnet.toml` | `/etc/x0x/config.toml` |
| Auto-update | enabled (fast iteration) | disabled (manual control) |
| Real users | no | **yes** |
| Tokens file | `tests/.vps-tokens-test.env` | `tests/.vps-tokens-prod.env` |
| Token var prefix | `TEST_<NODE>_<IP|TK>` | `PROD_<NODE>_<IP|TK>` |
| Banner | green, no hold | **red**, **5s Ctrl-C** window |

## How the selector works

- `tests/x0x_network.py` (Python) and `tests/x0x-network.sh` (Bash) are the
  single source of truth. Both expose a `--network {test,prod}` flag with
  `test` as the default.
- Calling the selector prints a loud banner identifying the targeted network
  (`TARGETING: TESTNET` in green, or `⚠️ TARGETING: PRODUCTION FLEET ⚠️` in red).
- For prod, the selector sleeps **5 seconds** before continuing so the operator
  has a window to Ctrl-C if they typed the wrong flag. Skip the hold with
  `X0X_NETWORK_NO_HOLD=1` (the soak harness sets this internally for per-window
  invocations).
- Token files are split per-network with different variable prefixes — sourcing
  the wrong file is loud (`PROD_NYC_TK` won't satisfy a script looking for
  `TEST_NYC_TK`).

## Adding a new test script

Python:

```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from x0x_network import select_network, banner, add_network_arg

parser = argparse.ArgumentParser()
add_network_arg(parser)         # adds --network {test,prod}
# … your own args …
args = parser.parse_args()

net = select_network(args)
banner(net)                     # prints banner; for prod, holds 5s
# now use net.api_port, net.gossip_port, net.token_for("nyc"), net.api_url("nyc")
```

Bash:

```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/x0x-network.sh"
x0x_network_select "$@"
set -- "${X0X_FILTERED_ARGS[@]+"${X0X_FILTERED_ARGS[@]}"}"
# now use $X0X_API_PORT, $X0X_GOSSIP_PORT, $X0X_SERVICE,
# $X0X_TOKEN_FILE, $X0X_TOKEN_VAR_PREFIX, x0x_token_for nyc, x0x_ip_for nyc
```

## What changed (2026-05-16)

Before: every test script targeted prod by default (port 12600). The 4h soak
that triggered the May 15 fleet-collapse-then-rollback exercise was running
*against production*. There was no way to soak without touching prod.

After: every test script defaults to a separate testnet. Production is opt-in
via `--network prod` and gated by a banner + 5s window. Token files are split
so no accidental cross-network use is possible.

See: tests/x0x_network.py, tests/x0x-network.sh, tests/e2e_deploy.sh,
tests/launch_readiness.py, tests/launch_soak.py.
