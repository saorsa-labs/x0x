"""Validate observations sampled inside a systemd fixture child, fail closed."""
import re


def fixture_identity(environ):
    """Keep access to the sudo caller's private paths, without running as root."""
    if "SUDO_UID" not in environ and "SUDO_GID" not in environ:
        return 65534, 65534
    values = [environ.get(name, "") for name in ("SUDO_UID", "SUDO_GID")]
    if any(not re.fullmatch(r"[0-9]+", value) for value in values):
        raise ValueError("invalid sudo fixture identity")
    uid, gid = map(int, values)
    if uid == 0 and gid == 0:
        return 65534, 65534
    if not (0 < uid < 2**32 - 1 and 0 < gid < 2**32 - 1):
        raise ValueError("fixture identity must be unprivileged")
    return uid, gid


def validate(receipt, parent_netns):
    if not isinstance(receipt, dict):
        raise ValueError("missing child isolation receipt")
    if receipt.get("namespace_changed") is not True:
        raise ValueError("child network namespace did not change")
    namespace = receipt.get("namespace")
    if not isinstance(namespace, str) or not re.fullmatch(r"net:\[\d+\]", namespace):
        raise ValueError("missing child network namespace")
    if not isinstance(parent_netns, str) or not re.fullmatch(r"net:\[\d+\]", parent_netns):
        raise ValueError("missing parent network namespace")
    if namespace == parent_netns:
        raise ValueError("child network namespace matches parent")
    if [row.get("ifname") for row in receipt.get("links", [])] != ["lo"]:
        raise ValueError("child interfaces are not loopback-only")
    routes = receipt.get("routes")
    if not isinstance(routes, dict) or set(routes) != {"-4", "-6"}:
        raise ValueError("missing child routes")
    for rows in routes.values():
        if not isinstance(rows, list) or any(
            row.get("dev") != "lo" or row.get("dst") == "default" or "gateway" in row
            for row in rows
        ):
            raise ValueError("child has external routes")
    for name in ("uid", "gid"):
        if type(receipt.get(name)) is not int or receipt[name] <= 0:
            raise ValueError("child has privileged identity")
    capabilities = receipt.get("capabilities")
    if not isinstance(capabilities, dict):
        raise ValueError("missing child capabilities")
    for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        value = capabilities.get(name)
        if not isinstance(value, str) or len(value) != 16 or int(value, 16) != 0:
            raise ValueError("child retains capabilities")
    if type(receipt.get("no_new_privs")) is not int or receipt["no_new_privs"] != 1:
        raise ValueError("child no_new_privs is unset")
