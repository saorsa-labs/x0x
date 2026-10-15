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

    def test_never_type_closes_at_the_function_body(self):
        # -> ! is a never type. The body stays test-only and the next function
        # stays production.
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                visible = self._call(kind, "visible")
                source = (
                    "#[cfg(test)]\n"
                    "fn helper() -> ! {\n"
                    f"    {hidden};\n"
                    "}\n"
                    f"fn prod() {{ {visible}; }}\n"
                )
                result = self.scan("src/never.rs", source)
                self._assert_rejected(result, kind)

    def test_expr_macro_stays_inside_the_attributed_statement(self):
        # matches! / vec! are part of the statement. They do not end it.
        for kind in ("expect", "unwrap", "panic"):
            hidden = self._call(kind, "hidden")
            visible = self._call(kind, "visible")
            shapes = {
                "if": (
                    "fn prod() {\n"
                    "    #[cfg(test)]\n"
                    f"    if matches!(Some(1), Some(_)) {{ {hidden}; }}\n"
                    f"    {visible};\n"
                    "}\n"
                ),
                "let": (
                    "fn prod() {\n"
                    "    #[cfg(test)]\n"
                    f"    let _ = vec![{hidden}];\n"
                    f"    {visible};\n"
                    "}\n"
                ),
                "array": (
                    "fn prod() {\n"
                    "    let _ = [\n"
                    "        #[cfg(test)]\n"
                    f"        vec![{hidden}],\n"
                    f"        {visible},\n"
                    "    ];\n"
                    "}\n"
                ),
                "not": (
                    "fn prod() {\n"
                    "    #[cfg(test)]\n"
                    f"    if !false {{ {hidden}; }}\n"
                    f"    {visible};\n"
                    "}\n"
                ),
            }
            for name, source in shapes.items():
                with self.subTest(kind=kind, shape=name):
                    result = self.scan("src/expr_macro.rs", source)
                    self._assert_rejected(result, kind)

    def test_return_type_brace_macro_is_not_the_function_body(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                visible = self._call(kind, "visible")
                source = (
                    "#[cfg(test)]\n"
                    "fn helper() -> unit!{} {\n"
                    f"    {hidden};\n"
                    "}\n"
                    f"fn prod() {{ {visible}; }}\n"
                )
                result = self.scan("src/ret_brace.rs", source)
                self._assert_rejected(result, kind)

    def test_signature_paren_macro_is_not_the_function_body(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                visible = self._call(kind, "visible")
                source = (
                    "#[cfg(test)]\n"
                    "fn helper() -> unit!() {\n"
                    f"    {hidden};\n"
                    "}\n"
                    f"fn prod() {{ {visible}; }}\n"
                )
                result = self.scan("src/ret_paren.rs", source)
                self._assert_rejected(result, kind)

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

    def test_array_closer_does_not_hide_later_call(self):
        # A ']' that ends the enclosing array also ends the attributed element.
        # A later array at the same depth is production.
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                visible = self._call(kind, "visible")
                source = (
                    "fn prod() {\n"
                    "    let _ = [\n"
                    "        #[cfg(test)]\n"
                    f"        {hidden}\n"
                    "    ];\n"
                    "    let _ = [\n"
                    "        {\n"
                    f"            {visible};\n"
                    "        }\n"
                    "    ];\n"
                    "}\n"
                )
                result = self.scan("src/array_closer.rs", source)
                self._assert_rejected(result, kind)

    def test_tuple_closer_does_not_hide_later_call(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                visible = self._call(kind, "visible")
                source = (
                    "fn prod() {\n"
                    "    let _ = (\n"
                    "        #[cfg(test)]\n"
                    f"        {hidden}\n"
                    "    );\n"
                    f"    {visible};\n"
                    "}\n"
                )
                result = self.scan("src/tuple_closer.rs", source)
                self._assert_rejected(result, kind)

    def test_attr_inside_brace_macro_input_is_production(self):
        # A macro can consume the attribute and emit the item unchanged.
        # The call inside that item stays production.
        for kind in ("expect", "unwrap", "panic"):
            visible = self._call(kind, "visible")
            shapes = {
                "inner": (
                    "macro_rules! emit { (#![cfg(test)] $item:item) => { $item }; }\n"
                    "emit! {\n"
                    "    #![cfg(test)]\n"
                    f"    pub fn prod() {{ {visible}; }}\n"
                    "}\n"
                    "pub fn witness() { prod(); }\n"
                ),
                "outer": (
                    "macro_rules! emit { (#[cfg(test)] $item:item) => { $item }; }\n"
                    "emit! {\n"
                    "    #[cfg(test)]\n"
                    f"    pub fn prod() {{ {visible}; }}\n"
                    "}\n"
                    "pub fn witness() { prod(); }\n"
                ),
            }
            for name, source in shapes.items():
                with self.subTest(kind=kind, shape=name):
                    result = self.scan("src/emit_macro.rs", source)
                    self.assertEqual(result.returncode, 1, result.stdout)
                    self.assertIn(visible, result.stdout)
                    self.assertIn(self._found(kind), result.stdout)

    def test_proved_module_still_hides_a_call_inside_a_macro(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                visible = self._call(kind, "visible")
                source = (
                    "#[cfg(test)]\n"
                    "mod tests {\n"
                    "    emit! {\n"
                    "        #[cfg(test)]\n"
                    f"        fn helper() {{ {hidden}; }}\n"
                    "    }\n"
                    "}\n"
                    f"fn prod() {{ {visible}; }}\n"
                )
                result = self.scan("src/proved_macro.rs", source)
                self._assert_rejected(result, kind)

    def test_inner_cfg_in_macro_args_does_not_exempt_the_file(self):
        # Brace depth zero is not crate scope. A macro can swallow the attribute.
        for kind in ("expect", "unwrap", "panic"):
            inside = self._call(kind, "inside")
            after = self._call(kind, "after")
            shapes = {
                "paren": (
                    "macro_rules! eat { ($($t:tt)*) => {} }\n"
                    "eat!(\n"
                    "    #![cfg(test)]\n"
                    f"    fn helper() {{ {inside}; }}\n"
                    ");\n"
                    f"fn prod() {{ {after}; }}\n"
                ),
                "bracket": (
                    "macro_rules! eat { ($($t:tt)*) => {} }\n"
                    "eat![\n"
                    "    #![cfg(test)]\n"
                    f"    fn helper() {{ {inside}; }}\n"
                    "];\n"
                    f"fn prod() {{ {after}; }}\n"
                ),
            }
            for name, source in shapes.items():
                with self.subTest(kind=kind, shape=name):
                    result = self.scan("src/macro_cfg.rs", source)
                    self._assert_both_production(result, kind)

    def test_nested_inner_cfg_closes_with_the_module(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                visible = self._call(kind, "visible")
                source = (
                    "mod support {\n"
                    "    #![cfg(test)]\n"
                    f"    fn helper() {{ {hidden}; }}\n"
                    "}\n"
                    f"fn prod() {{ {visible}; }}\n"
                )
                result = self.scan("src/nested_cfg.rs", source)
                self._assert_rejected(result, kind)

    def test_macro_item_closes_before_the_next_function(self):
        for kind in ("expect", "unwrap", "panic"):
            hidden = self._call(kind, "hidden")
            visible = self._call(kind, "visible")
            shapes = {
                "brace": (
                    "#[cfg(test)]\n"
                    "make! {\n"
                    f"    {hidden};\n"
                    "}\n"
                    f"fn prod() {{ {visible}; }}\n"
                ),
                "paren": (
                    "#[cfg(test)]\n"
                    f"make!({hidden});\n"
                    f"fn prod() {{ {visible}; }}\n"
                ),
                "macro_rules": (
                    "#[cfg(test)]\n"
                    "macro_rules! make {\n"
                    f"    () => {{ {hidden}; }};\n"
                    "}\n"
                    f"fn prod() {{ {visible}; }}\n"
                ),
            }
            for name, source in shapes.items():
                with self.subTest(kind=kind, shape=name):
                    result = self.scan("src/macro_item.rs", source)
                    self._assert_rejected(result, kind)

    def test_slash_slash_inside_a_string_does_not_hide_a_call(self):
        result = self.scan(
            "src/production.rs",
            'fn prod() { let _ = "http://".expect("visible"); }\n',
        )
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('.expect("visible")', result.stdout)
        self.assertIn("FOUND: .expect() calls in production code", result.stdout)
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                visible = self._call(kind, "visible")
                source = f'fn prod() {{ let _ = "http://"; {visible}; }}\n'
                result = self.scan("src/production.rs", source)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(visible, result.stdout)
                self.assertIn(self._found(kind), result.stdout)

    def test_block_comment_and_doc_comment_calls_are_accepted(self):
        self.assert_clean(self.scan("src/production.rs", '/* value.expect("comment"); */\n'))
        self.assert_clean(self.scan("src/production.rs", "/* value.unwrap() */\n"))
        self.assert_clean(self.scan("src/production.rs", '/* panic!("comment") */\n'))
        self.assert_clean(self.scan("src/production.rs", '/// value.expect("comment");\n'))
        self.assert_clean(self.scan("src/production.rs", '//! value.expect("comment");\n'))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner", type=Path, default=SCANNER)
    args, unittest_args = parser.parse_known_args()
    SCANNER = args.scanner.resolve(strict=True)
    unittest.main(argv=[__file__, *unittest_args], verbosity=2)
