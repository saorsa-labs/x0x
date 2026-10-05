"""Validate observations sampled inside a systemd fixture child, fail closed."""


def validate(receipt):
    if not isinstance(receipt, dict):
        raise ValueError("missing child isolation receipt")
    if receipt.get("namespace_changed") is not True:
        raise ValueError("child network namespace did not change")
    namespace = receipt.get("namespace")
    if not isinstance(namespace, str) or not namespace.startswith("net:["):
        raise ValueError("missing child network namespace")
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
