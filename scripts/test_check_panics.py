#!/usr/bin/env python3
"""Run the real shell scanner over inert text; never compile or execute Rust."""

import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCANNER = Path(__file__).resolve().with_name("check-panics.sh")


class PanicScanner(unittest.TestCase):
    def scan(self, relative, source):
        with tempfile.TemporaryDirectory(prefix="x0x-panic-scanner-") as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "x0x").mkdir()
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")
            result = subprocess.run(
                ["bash", str(SCANNER)],
                cwd=root,
                env={**os.environ, "LC_ALL": "C"},
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        print(f"\n{self.id()}: scanner exit {result.returncode}", flush=True)
        print(result.stdout, end="", flush=True)
        print(result.stderr, end="", flush=True)
        self.assertEqual(result.stderr, "", "scanner regex/tool errors must be visible")
        return result

    def assert_clean(self, result):
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("PASS: No .expect() calls in production code", result.stdout)
        self.assertIn("All checks passed", result.stdout)

    def _call(self, kind, label):
        if kind == "unwrap":
            return f"{label}.unwrap()"
        if kind == "expect":
            return f'{label}.expect("{label}")'
        if kind == "panic":
            return f'panic!("{label}")'
        raise AssertionError(kind)

    def _found(self, kind):
        return {
            "unwrap": "FOUND: .unwrap() calls in production code",
            "expect": "FOUND: .expect() calls in production code",
            "panic": "FOUND: panic! macro",
        }[kind]

    def _assert_rejected(self, result, kind):
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(self._call(kind, "visible"), result.stdout)
        self.assertNotIn("hidden", result.stdout)
        self.assertIn(self._found(kind), result.stdout)

    def _assert_both_production(self, result, kind):
        """Unclassified bytes count as production, and so does the call after them."""
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(self._call(kind, "inside"), result.stdout)
        self.assertIn(self._call(kind, "after"), result.stdout)
        self.assertIn(self._found(kind), result.stdout)

    def test_production_expect_is_rejected(self):
        result = self.scan("src/production.rs", 'fn f() { value.expect("required"); }\n')
        self.assertEqual(result.returncode, 1, "production expect must fail the real scanner")
        self.assertIn('src/production.rs:1:fn f() { value.expect("required"); }', result.stdout)
        self.assertIn("FOUND: .expect() calls in production code", result.stdout)
        self.assertIn("Found 1 issue(s)", result.stdout)

    def test_clean_production_is_accepted(self):
        self.assert_clean(self.scan("src/production.rs", "fn f() { value.map_err(convert)?; }\n"))

    def test_inner_cfg_test_is_accepted(self):
        self.assert_clean(self.scan("src/helper.rs", '#![cfg(test)]\nfn f() { value.expect("test"); }\n'))

    def test_comment_expect_is_accepted(self):
        self.assert_clean(self.scan("src/production.rs", '// value.expect("comment");\n'))

    def test_lookalikes_are_accepted(self):
        self.assert_clean(self.scan("src/production.rs", 'valuexexpect("text");\nvalue.expect_value;\n'))

    def test_tests_path_is_accepted(self):
        self.assert_clean(self.scan("src/tests.rs", 'fn f() { value.expect("test"); }\n'))

    def test_production_call_after_closed_cfg_test_module_is_rejected(self):
        # Issue #1254: the scanner used to keep the test flag set after the
        # first #[cfg(test)], so the production call was invisible.
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                visible = self._call(kind, "visible")
                source = (
                    "#[cfg(test)]\n"
                    "mod tests {\n"
                    f"    fn t() {{ {hidden}; }}\n"
                    "}\n"
                    f"fn prod() {{ {visible}; }}\n"
                )
                result = self.scan("src/after_cfg.rs", source)
                self._assert_rejected(result, kind)

    def test_call_inside_cfg_test_module_is_accepted(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                source = (
                    "#[cfg(test)]\n"
                    "mod tests {\n"
                    f"    fn t() {{ {hidden}; }}\n"
                    "}\n"
                    "fn prod() { let _ = ready?; }\n"
                )
                result = self.scan("src/module.rs", source)
                self.assert_clean(result)
                self.assertNotIn("hidden", result.stdout)

    def test_production_call_after_cfg_test_use_is_rejected(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                visible = self._call(kind, "visible")
                source = (
                    "#[cfg(test)]\n"
                    "use std::fs;\n"
                    f"fn prod() {{ {visible}; }}\n"
                )
                result = self.scan("src/early_use.rs", source)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(visible, result.stdout)
                self.assertIn(self._found(kind), result.stdout)

    def test_same_line_closer_does_not_hide_production_call(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                visible = self._call(kind, "visible")
                source = (
                    "#[cfg(test)]\n"
                    f"mod tests {{ fn t() {{ {hidden}; }} }} "
                    f"fn prod() {{ {visible}; }}\n"
                )
                result = self.scan("src/same_line.rs", source)
                # grep prints the whole line, so the test call is visible in the
                # same report as the production call. The production call must
                # still fail the scan.
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(visible, result.stdout)
                self.assertIn(self._found(kind), result.stdout)

    def test_unclosed_cfg_test_item_is_production(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                inside = self._call(kind, "inside")
                source = (
                    "#[cfg(test)]\n"
                    "mod tests {\n"
                    f"    fn t() {{ {inside}; }}\n"
                )
                result = self.scan("src/unclosed.rs", source)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(inside, result.stdout)
                self.assertIn(self._found(kind), result.stdout)

    def test_never_type_is_production(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                inside = self._call(kind, "inside")
                after = self._call(kind, "after")
                source = (
                    "#[cfg(test)]\n"
                    "fn helper() -> ! {\n"
                    f"    {inside};\n"
                    "}\n"
                    f"fn prod() {{ {after}; }}\n"
                )
                result = self.scan("src/never.rs", source)
                self._assert_both_production(result, kind)

    def test_expr_macro_is_production(self):
        for kind in ("expect", "unwrap", "panic"):
            inside = self._call(kind, "inside")
            after = self._call(kind, "after")
            shapes = {
                "if": (
                    "fn prod() {\n"
                    "    #[cfg(test)]\n"
                    f"    if matches!(Some(1), Some(_)) {{ {inside}; }}\n"
                    f"    {after};\n"
                    "}\n"
                ),
                "let": (
                    "fn prod() {\n"
                    "    #[cfg(test)]\n"
                    f"    let _ = vec![{inside}];\n"
                    f"    {after};\n"
                    "}\n"
                ),
                "array": (
                    "fn prod() {\n"
                    "    let _ = [\n"
                    "        #[cfg(test)]\n"
                    f"        vec![{inside}],\n"
                    f"        {after},\n"
                    "    ];\n"
                    "}\n"
                ),
            }
            for name, source in shapes.items():
                with self.subTest(kind=kind, shape=name):
                    result = self.scan("src/expr_macro.rs", source)
                    self._assert_both_production(result, kind)

    def test_return_type_brace_macro_is_production(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                inside = self._call(kind, "inside")
                after = self._call(kind, "after")
                source = (
                    "#[cfg(test)]\n"
                    "fn helper() -> unit!{} {\n"
                    f"    {inside};\n"
                    "}\n"
                    f"fn prod() {{ {after}; }}\n"
                )
                result = self.scan("src/ret_brace.rs", source)
                self._assert_both_production(result, kind)

    def test_signature_macro_is_production(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                inside = self._call(kind, "inside")
                after = self._call(kind, "after")
                source = (
                    "#[cfg(test)]\n"
                    "fn helper() -> unit!() {\n"
                    f"    {inside};\n"
                    "}\n"
                    f"fn prod() {{ {after}; }}\n"
                )
                result = self.scan("src/ret_paren.rs", source)
                self._assert_both_production(result, kind)

    def test_comment_before_generic_is_production(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                inside = self._call(kind, "inside")
                after = self._call(kind, "after")
                source = (
                    "#[cfg(test)]\n"
                    "fn helper() -> Foo /* note */ <u8, {1}> {\n"
                    f"    {inside};\n"
                    "}\n"
                    f"fn prod() {{ {after}; }}\n"
                )
                result = self.scan("src/generic_comment.rs", source)
                self._assert_both_production(result, kind)

    def test_if_let_brace_does_not_hide_following_call(self):
        # The closing brace is the item end. '=' is not an initializer exception.
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                visible = self._call(kind, "visible")
                source = (
                    "fn prod() {\n"
                    "    #[cfg(test)]\n"
                    f"    if let Some(_) = Some(1) {{ {hidden}; }}\n"
                    f"    {visible};\n"
                    "}\n"
                )
                result = self.scan("src/if_let.rs", source)
                self._assert_rejected(result, kind)

    def test_bare_cr_does_not_hide_production_call(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                visible = self._call(kind, "visible")
                source = (
                    "/* a\rb */\n"
                    "#[cfg(test)]\n"
                    f"fn helper() {{ {hidden}; }}\n"
                    f"fn prod() {{ {visible}; }}\n"
                )
                result = self.scan("src/bare_cr.rs", source)
                self._assert_rejected(result, kind)

    def test_finished_test_fn_does_not_hide_following_call(self):
        # #[test] and #[tokio::test] are identified attributes. The function
        # closes at its brace; the next item is production.
        for kind in ("expect", "unwrap", "panic"):
            hidden = self._call(kind, "hidden")
            visible = self._call(kind, "visible")
            shapes = {
                "test": (
                    "#[test]\n"
                    f"fn helper() {{ {hidden}; }}\n"
                    f"fn prod() {{ {visible}; }}\n"
                ),
                "tokio": (
                    "#[tokio::test]\n"
                    f"async fn helper() {{ {hidden}; }}\n"
                    f"fn prod() {{ {visible}; }}\n"
                ),
                "tokio-args": (
                    '#[tokio::test(flavor = "current_thread", start_paused = true)]\n'
                    f"async fn helper() {{ {hidden}; }}\n"
                    f"fn prod() {{ {visible}; }}\n"
                ),
            }
            for name, source in shapes.items():
                with self.subTest(kind=kind, shape=name):
                    result = self.scan("src/test_fn.rs", source)
                    self._assert_rejected(result, kind)

    def test_unrecognized_cfg_attribute_is_production(self):
        # Only an exact test attribute starts a region. cfg(any(test, ...))
        # is also production code on the other predicate.
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                inside = self._call(kind, "inside")
                after = self._call(kind, "after")
                source = (
                    '#[cfg(any(test, target_os = "linux"))]\n'
                    f"fn helper() {{ {inside}; }}\n"
                    f"fn prod() {{ {after}; }}\n"
                )
                result = self.scan("src/cfg_any.rs", source)
                self._assert_both_production(result, kind)

    def test_string_brace_does_not_hide_production_call(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                visible = self._call(kind, "visible")
                source = (
                    "#[cfg(test)]\n"
                    "mod tests {\n"
                    "    fn t() {\n"
                    '        let s = "open\n'
                    "{ brace\n"
                    '";\n'
                    f"        {hidden};\n"
                    "    }\n"
                    "}\n"
                    f"fn prod() {{ {visible}; }}\n"
                )
                result = self.scan("src/string_brace.rs", source)
                self._assert_rejected(result, kind)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner", type=Path, default=SCANNER)
    args, unittest_args = parser.parse_known_args()
    SCANNER = args.scanner.resolve(strict=True)
    unittest.main(argv=[__file__, *unittest_args], verbosity=2)
