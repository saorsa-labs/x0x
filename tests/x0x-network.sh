# shellcheck shell=bash
# x0x-network.sh — sourceable network selector for tests/*.sh scripts.
#
# Mirror of tests/x0x_network.py. Default network is TESTNET. To target
# production, the calling script must pass --network prod, which triggers
# a loud red banner + 5s Ctrl-C window before any action is taken.
#
# Usage in a script::
#
#     #!/usr/bin/env bash
#     set -euo pipefail
#     SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#     source "$SCRIPT_DIR/x0x-network.sh"
#     x0x_network_select "$@"            # parses --network, prints banner
#     # now: $X0X_NETWORK, $X0X_API_PORT, $X0X_GOSSIP_PORT,
#     #      $X0X_SERVICE, $X0X_TOKEN_FILE, $X0X_NODES (space-separated IPs)
#     #      x0x_token_for nyc           # → echoes the token
#     #      x0x_ip_for nyc              # → echoes the IP

# Fleet (same IPs both networks; only ports + tokens + service differ)
X0X_NODES_NAMES="nyc sfo helsinki nuremberg singapore sydney"
declare -A X0X_NODE_IPS=(
    [nyc]="142.93.199.50"
    [sfo]="147.182.234.192"
    [helsinki]="65.21.157.229"
    [nuremberg]="116.203.101.172"
    [singapore]="152.42.210.67"
    [sydney]="170.64.176.102"
)

x0x_ip_for() {
    local node="$1"
    echo "${X0X_NODE_IPS[$node]:-}"
}

x0x_token_for() {
    # Read token from current network's token file. Refuses to fall through
    # to another network's file even if vars are exported.
    local node_upper
    node_upper="$(echo "$1" | tr '[:lower:]' '[:upper:]')"
    local var="${X0X_TOKEN_VAR_PREFIX}_${node_upper}_TK"
    # shellcheck disable=SC1090
    source "$X0X_TOKEN_FILE"
    echo "${!var:-}"
}

x0x_network_select() {
    # Parse --network from "$@". Default: test.
    local net="test"
    local args=("$@")
    local new_args=()
    local i=0
    while [ $i -lt ${#args[@]} ]; do
        case "${args[$i]}" in
            --network)
                net="${args[$((i+1))]:-}"
                i=$((i+2))
                ;;
            --network=*)
                net="${args[$i]#--network=}"
                i=$((i+1))
                ;;
            *)
                new_args+=("${args[$i]}")
                i=$((i+1))
                ;;
        esac
    done

    case "$net" in
        test|prod) ;;
        *)
            echo "ERROR: --network must be 'test' or 'prod', got '$net'" >&2
            return 2
            ;;
    esac

    export X0X_NETWORK="$net"
    if [ "$net" = "prod" ]; then
        export X0X_API_PORT=12600
        export X0X_GOSSIP_PORT=5483
        export X0X_SERVICE="x0xd.service"
        # Prod owns the canonical binary path; its self-update writes here.
        export X0X_BINARY_PATH="/opt/x0x/x0xd"
        export X0X_TOKEN_FILE="$(dirname "${BASH_SOURCE[0]}")/.vps-tokens-prod.env"
        export X0X_TOKEN_VAR_PREFIX="PROD"
    else
        export X0X_API_PORT=13600
        export X0X_GOSSIP_PORT=6483
        export X0X_SERVICE="x0xd-testnet.service"
        # Testnet has its OWN binary path so prod self-upgrades cannot clobber
        # the testnet binary (the shared /opt/x0x/x0xd previously caused prod's
        # auto-upgrade to overwrite a freshly-deployed testnet build).
        export X0X_BINARY_PATH="/opt/x0x/x0xd-testnet"
        export X0X_TOKEN_FILE="$(dirname "${BASH_SOURCE[0]}")/.vps-tokens-test.env"
        export X0X_TOKEN_VAR_PREFIX="TEST"
    fi
    export X0X_NODES_IPS=""
    for n in $X0X_NODES_NAMES; do
        X0X_NODES_IPS+="${X0X_NODE_IPS[$n]} "
    done

    # Reset positional args to the filtered set (network flag consumed)
    set -- "${new_args[@]+"${new_args[@]}"}"

    x0x_network_banner

    # Caller continues with the rest of "$@" via "${X0X_FILTERED_ARGS[@]}"
    X0X_FILTERED_ARGS=("${new_args[@]+"${new_args[@]}"}")
}

x0x_export_legacy_token_vars() {
    # Compatibility shim for scripts that pre-date the --network contract
    # and refer to plain ${NYC_TK} / ${NYC_IP} / ${SFO_TK} / etc.
    # Call after x0x_network_select. Re-exports the right-network tokens
    # under the unprefixed legacy names so existing scripts work unchanged.
    local node node_upper
    for node in $X0X_NODES_NAMES; do
        node_upper="$(echo "$node" | tr '[:lower:]' '[:upper:]')"
        eval "${node_upper}_IP=\"$(x0x_ip_for "$node")\""
        eval "${node_upper}_TK=\"$(x0x_token_for "$node")\""
        export "${node_upper}_IP" "${node_upper}_TK"
    done
}

x0x_network_banner() {
    # 70-char loud banner. Prod is red-on-white with 5s Ctrl-C hold;
    # test is green-on-white, no hold.
    local width=70
    local bar1 bar2
    if [ "$X0X_NETWORK" = "prod" ]; then
        bar1="$(printf '═%.0s' $(seq 1 $((width-2))))"
        printf '\n\033[1;41;97m╔%s╗\n' "$bar1" >&2
        printf '║%*s║\n' $((width-2)) "" >&2
        printf '║\033[1;41;97m%s\033[0m\033[1;41;97m║\n' \
            "$(printf '%*s' $(((width-2 + 32)/2)) '⚠️  TARGETING: PRODUCTION FLEET  ⚠️')$(printf '%*s' $(((width-2 - 32)/2)) '')" >&2
        printf '║%*s║\n' $((width-2)) "$(printf '%*s' $(((width-2 + 36)/2)) "UDP $X0X_GOSSIP_PORT / TCP $X0X_API_PORT / REAL USERS")" >&2
        printf '║%*s║\n' $((width-2)) "$(printf '%*s' $(((width-2 + 28)/2)) "service: $X0X_SERVICE")" >&2
        printf '║%*s║\n' $((width-2)) "$(printf '%*s' $(((width-2 + 20)/2)) "Ctrl-C in 5s to abort")" >&2
        printf '║%*s║\n' $((width-2)) "" >&2
        printf '╚%s╝\033[0m\n\n' "$bar1" >&2
        if [ "${X0X_NETWORK_NO_HOLD:-0}" != "1" ]; then
            sleep 5 || { echo "Aborted by operator." >&2; exit 130; }
        fi
    else
        bar2="$(printf '─%.0s' $(seq 1 $((width-2))))"
        printf '\n\033[1;42;30m┌%s┐\n' "$bar2" >&2
        printf '│%*s│\n' $((width-2)) "$(printf '%*s' $(((width-2 + 18)/2)) 'TARGETING: TESTNET')" >&2
        printf '│%*s│\n' $((width-2)) "$(printf '%*s' $(((width-2 + 40)/2)) "UDP $X0X_GOSSIP_PORT / TCP $X0X_API_PORT / no real users")" >&2
        printf '│%*s│\n' $((width-2)) "$(printf '%*s' $(((width-2 + 30)/2)) "service: $X0X_SERVICE")" >&2
        printf '└%s┘\033[0m\n\n' "$bar2" >&2
    fi
}
