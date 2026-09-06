#!/usr/bin/env python3
"""Static synthetic controls; never starts x0xd or opens a network socket."""
import importlib.util
from pathlib import Path
import tempfile


ROOT = Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    driver = load("mixed-driver")
    collector = load("collect-evidence")
    positive = [{"name": name, "status": "pass"}
                for name in sorted(driver.EXPECTED_RESULT_NAMES)]
    two_failure = [{"name": name, "status": "fail", "error": "synthetic"}
                   for name in sorted(driver.EXPECTED_RESULT_NAMES)]
    assert driver.exact_result_shape(positive)
    assert driver.exact_result_shape(two_failure)
    assert all(row["status"] == "fail" for row in two_failure)
    for malformed in ([], [{"name": "only-one"}], {}, None, ["bad"]):
        assert not driver.exact_result_shape(malformed)
    assert collector.sanitize({"status": "pass", "result_shape_valid": True,
                               "module_sha256": "a" * 64,
                               "result": positive})["result"] == positive
    assert collector.sanitize({"status": "fail", "result_shape_valid": True,
                               "result": two_failure})["status"] == "fail"
    for malformed in ({}, {"result": []}, {"result": "bad"},
                      {"result": [{"name": "bad"}, "bad"]}):
        try:
            collector.sanitize(malformed)
        except ValueError:
            pass
        else:
            raise AssertionError(f"malformed result accepted: {malformed!r}")
    try:
        collector.sanitize({"result": [{"name": row["name"],
                                             "status": "pass",
                                             "scope": "contains api-token"}
                                            for row in positive],
                            "status": "pass"})
    except ValueError:
        pass
    else:
        raise AssertionError("secret marker accepted")
    with tempfile.TemporaryDirectory(prefix="x0x-517-controls-") as temp:
        root = Path(temp)
        real = root / "real"
        real.write_text("safe")
        link = root / "link"
        link.symlink_to(real)
        try:
            collector.regular(link)
        except ValueError:
            pass
        else:
            raise AssertionError("symlink accepted as receipt")
    print("PASS: positive, two-failure, empty, missing, malformed, secret, symlink controls")


if __name__ == "__main__":
    main()
