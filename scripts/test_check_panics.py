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
        # Retain actual scanner output even for passing synthetic controls.
        print(f"\n{self.id()}: scanner exit {result.returncode}", flush=True)
        print(result.stdout, end="", flush=True)
        print(result.stderr, end="", flush=True)
        self.assertEqual(result.stderr, "", "scanner regex/tool errors must be visible")
        return result

    def assert_clean(self, result):
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("PASS: No .expect() calls in production code", result.stdout)
        self.assertIn("All checks passed", result.stdout)

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
        # Exercises the shared pattern's ERE consumer, not just BRE matching.
        self.assert_clean(self.scan("src/production.rs", '// value.expect("comment");\n'))

    def test_lookalikes_are_accepted(self):
        self.assert_clean(self.scan("src/production.rs", 'valuexexpect("text");\nvalue.expect_value;\n'))

    def test_tests_path_is_accepted(self):
        self.assert_clean(self.scan("src/tests.rs", 'fn f() { value.expect("test"); }\n'))

    def test_production_expect_after_closed_cfg_test_module_is_rejected(self):
        # The scanner used to keep the test flag set after the first
        # #[cfg(test)], so this production expect was invisible.
        source = (
            "#[cfg(test)]\n"
            "mod tests {\n"
            '    fn t() { value.expect("hidden"); }\n'
            "}\n"
            'fn prod() { value.expect("visible"); }\n'
        )
        result = self.scan("src/after_cfg.rs", source)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('src/after_cfg.rs:5:fn prod() { value.expect("visible"); }', result.stdout)
        self.assertNotIn("hidden", result.stdout)
        self.assertIn("FOUND: .expect() calls in production code", result.stdout)

    def test_expect_inside_cfg_test_module_is_accepted(self):
        source = (
            "#[cfg(test)]\n"
            "mod tests {\n"
            '    fn t() { value.expect("hidden"); }\n'
            "}\n"
            "fn prod() { let _ = ready?; }\n"
        )
        self.assert_clean(self.scan("src/module.rs", source))

    def test_production_expect_after_cfg_test_use_is_rejected(self):
        source = (
            "#[cfg(test)]\n"
            "use std::fs;\n"
            'fn prod() { value.expect("visible"); }\n'
        )
        result = self.scan("src/early_use.rs", source)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("src/early_use.rs:3:", result.stdout)
        self.assertNotIn("std::fs", result.stdout)
        self.assertIn('value.expect("visible")', result.stdout)

    def test_tokio_test_does_not_hide_following_production_expect(self):
        source = (
            "#[cfg(test)]\n"
            "use std::future::Future;\n"
            "#[tokio::test]\n"
            'async fn t() { value.expect("hidden"); }\n'
            'fn prod() { value.expect("visible"); }\n'
        )
        result = self.scan("src/tokio_test.rs", source)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("src/tokio_test.rs:5:", result.stdout)
        self.assertNotIn("hidden", result.stdout)

    def test_cfg_test_block_does_not_hide_following_production_expect(self):
        source = (
            "fn prod() {\n"
            "    #[cfg(test)]\n"
            "    {\n"
            '        value.expect("hidden");\n'
            "    }\n"
            '    value.expect("visible");\n'
            "}\n"
        )
        result = self.scan("src/statement.rs", source)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("src/statement.rs:6:", result.stdout)
        self.assertNotIn("hidden", result.stdout)

    def test_escaped_newline_string_does_not_hide_following_production_expect(self):
        source = (
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    fn dump() -> String {\n"
            '        let _ = value.expect("hidden");\n'
            "        format!(\n"
            '            "x = {{\\n\\\n'
            "             \\targuments = {{\\n{args}\\t}}\\n\\\n"
            '             }}\\n",\n'
            "        )\n"
            "    }\n"
            "}\n"
            'fn prod() { value.expect("visible"); }\n'
        )
        result = self.scan("src/format_string.rs", source)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("visible", result.stdout)
        self.assertNotIn("hidden", result.stdout)

    def test_cfg_all_test_module_does_not_hide_following_production_expect(self):
        source = (
            "#[cfg(all(test, unix))]\n"
            "mod tests {\n"
            '    fn t() { value.expect("hidden"); }\n'
            "}\n"
            'fn prod() { value.expect("visible"); }\n'
        )
        result = self.scan("src/cfg_all.rs", source)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("src/cfg_all.rs:5:", result.stdout)
        self.assertNotIn("hidden", result.stdout)

    def test_unescaped_multiline_string_does_not_hide_following_production_expect(self):
        # A string that spans lines without a backslash must stay open until
        # its closing quote. Counting the brace inside it leaves the test
        # module open and hides the production expect.
        source = (
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    fn t() {\n"
            '        let s = "open\n'
            "{ brace\n"
            '";\n'
            '        value.expect("hidden");\n'
            "    }\n"
            "}\n"
            'fn prod() { value.expect("visible"); }\n'
        )
        result = self.scan("src/multiline_string.rs", source)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('value.expect("visible")', result.stdout)
        self.assertNotIn("hidden", result.stdout)

    def test_nested_block_comment_does_not_hide_following_production_expect(self):
        source = (
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    fn t() {\n"
            "        /* outer /* inner */ { */\n"
            '        value.expect("hidden");\n'
            "    }\n"
            "}\n"
            'fn prod() { value.expect("visible"); }\n'
        )
        result = self.scan("src/nested_comment.rs", source)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('value.expect("visible")', result.stdout)
        self.assertNotIn("hidden", result.stdout)

    def test_generic_const_brace_does_not_report_test_helper_expect(self):
        source = (
            "#[cfg(test)]\n"
            "fn helper() -> std::array::IntoIter<u8, { 1 }> {\n"
            '    value.expect("hidden");\n'
            "}\n"
            'fn prod() { value.expect("visible"); }\n'
        )
        result = self.scan("src/generic_brace.rs", source)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('value.expect("visible")', result.stdout)
        self.assertNotIn("hidden", result.stdout)

    def test_production_expect_on_same_line_as_test_item_close_is_rejected(self):
        source = (
            "#[cfg(test)]\n"
            'mod tests { fn t() { value.expect("hidden"); } } '
            'fn prod() { value.expect("visible"); }\n'
        )
        result = self.scan("src/same_line.rs", source)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('value.expect("visible")', result.stdout)

    def _call(self, kind, label):
        if kind == "unwrap":
            return f"{label}.unwrap()"
        if kind == "expect":
            return f'{label}.expect("{label}")'
        if kind == "panic":
            return f'panic!("{label}")'
        raise AssertionError(kind)

    def _assert_rejected(self, result, kind):
        found = {
            "unwrap": "FOUND: .unwrap() calls in production code",
            "expect": "FOUND: .expect() calls in production code",
            "panic": "FOUND: panic! macro",
        }[kind]
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(self._call(kind, "visible"), result.stdout)
        self.assertNotIn("hidden", result.stdout)
        self.assertIn(found, result.stdout)

    def test_production_unwrap_is_rejected(self):
        result = self.scan("src/production.rs", "fn f() { visible.unwrap(); }\n")
        self._assert_rejected(result, "unwrap")

    def test_production_panic_is_rejected(self):
        result = self.scan("src/production.rs", 'fn f() { panic!("visible"); }\n')
        self._assert_rejected(result, "panic")

    def test_unwrap_inside_cfg_test_module_is_accepted(self):
        source = (
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    fn t() { hidden.unwrap(); }\n"
            "}\n"
            "fn prod() { let _ = ready?; }\n"
        )
        result = self.scan("src/module.rs", source)
        self.assert_clean(result)
        self.assertNotIn("hidden", result.stdout)

    def test_panic_inside_cfg_test_module_is_accepted(self):
        source = (
            "#[cfg(test)]\n"
            "mod tests {\n"
            '    fn t() { panic!("hidden"); }\n'
            "}\n"
            "fn prod() { let _ = ready?; }\n"
        )
        result = self.scan("src/module.rs", source)
        self.assert_clean(result)
        self.assertNotIn("hidden", result.stdout)

    def test_production_unwrap_after_closed_cfg_test_module_is_rejected(self):
        source = (
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    fn t() { hidden.unwrap(); }\n"
            "}\n"
            "fn prod() { visible.unwrap(); }\n"
        )
        result = self.scan("src/after_cfg.rs", source)
        self._assert_rejected(result, "unwrap")

    def test_production_panic_after_closed_cfg_test_module_is_rejected(self):
        source = (
            "#[cfg(test)]\n"
            "mod tests {\n"
            '    fn t() { panic!("hidden"); }\n'
            "}\n"
            'fn prod() { panic!("visible"); }\n'
        )
        result = self.scan("src/after_cfg.rs", source)
        self._assert_rejected(result, "panic")

    def test_const_comparison_does_not_hide_following_production_call(self):
        # `<` in `if 1 < 2` is a comparison. Counting it as a generic made the
        # brace-skipper ignore the function body, so the test region never closed.
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                visible = self._call(kind, "visible")
                source = (
                    "#[cfg(test)]\n"
                    "fn helper() -> [u8; if 1 < 2 { 1 } else { 0 }] { [0; 1] }\n"
                    f"fn prod() {{ {visible}; }}\n"
                )
                result = self.scan("src/const_cmp.rs", source)
                self._assert_rejected(result, kind)
                source = (
                    "#[cfg(test)]\n"
                    "fn helper() -> [u8; if 1 < 2 { 1 } else { 0 }] {\n"
                    f"    {hidden}\n"
                    "}\n"
                    f"fn prod() {{ {visible}; }}\n"
                )
                result = self.scan("src/const_cmp_body.rs", source)
                self._assert_rejected(result, kind)
                source = (
                    "#[cfg(test)]\n"
                    "fn helper() -> [u8; if 1 <= 2 { 1 } else { 0 }] { [0; 1] }\n"
                    f"fn prod() {{ {visible}; }}\n"
                )
                result = self.scan("src/const_le.rs", source)
                self._assert_rejected(result, kind)

    def test_ident_comparison_in_const_expr_does_not_hide_production_call(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                visible = self._call(kind, "visible")
                source = (
                    "#[cfg(test)]\n"
                    "fn helper() -> [u8; if a < b { 1 } else { 0 }] {\n"
                    f"    {hidden}\n"
                    "}\n"
                    f"fn prod() {{ {visible}; }}\n"
                )
                result = self.scan("src/const_cmp_ident.rs", source)
                self._assert_rejected(result, kind)

    def test_const_comparison_test_helper_call_is_accepted(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                source = (
                    "#[cfg(test)]\n"
                    "fn helper() -> [u8; if 1 < 2 { 1 } else { 0 }] {\n"
                    f"    {hidden};\n"
                    "}\n"
                    "fn prod() { let _ = ready?; }\n"
                )
                result = self.scan("src/const_cmp_only.rs", source)
                self.assert_clean(result)
                self.assertNotIn("hidden", result.stdout)

    def test_comparison_inside_const_generic_does_not_hide_production_call(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                visible = self._call(kind, "visible")
                source = (
                    "#[cfg(test)]\n"
                    "fn helper() -> std::array::IntoIter<u8, { if 1 < 2 { 1 } else { 0 } }> {\n"
                    f"    {hidden}\n"
                    "}\n"
                    f"fn prod() {{ {visible}; }}\n"
                )
                result = self.scan("src/const_generic_cmp.rs", source)
                self._assert_rejected(result, kind)

    def test_nested_inner_cfg_test_does_not_hide_following_production_call(self):
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
                result = self.scan("src/nested_inner.rs", source)
                self._assert_rejected(result, kind)

    def test_nested_inner_cfg_test_helper_call_is_accepted(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                source = (
                    "mod support {\n"
                    "    #![cfg(test)]\n"
                    f"    fn helper() {{ {hidden}; }}\n"
                    "}\n"
                    "fn prod() { let _ = ready?; }\n"
                )
                result = self.scan("src/nested_inner_only.rs", source)
                self.assert_clean(result)
                self.assertNotIn("hidden", result.stdout)

    def test_cfg_all_quoted_comma_is_production(self):
        # `--cfg 'custom="a,test,b"'` does not make this function test-only.
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                visible = self._call(kind, "visible")
                source = f'#[cfg(all(custom = "a,test,b"))]\nfn prod() {{ {visible}; }}\n'
                result = self.scan("src/cfg_quoted.rs", source)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(visible, result.stdout)

    def test_cfg_all_test_with_quoted_comma_still_hides_test_call(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                visible = self._call(kind, "visible")
                source = (
                    '#[cfg(all(test, feature = "a,b"))]\n'
                    "mod tests {\n"
                    f"    fn t() {{ {hidden}; }}\n"
                    "}\n"
                    f"fn prod() {{ {visible}; }}\n"
                )
                result = self.scan("src/cfg_all_quoted.rs", source)
                self._assert_rejected(result, kind)

    def test_cfg_comment_and_raw_string_are_not_test_predicates(self):
        # A comment or raw string can contain the letters `test` without
        # being a predicate. Treating either as code exempts production.
        attrs = (
            "#[cfg(all(/* ,test, */ unix))]",
            '#[cfg(all(custom = r#"a",test,"b"#))]',
        )
        for kind in ("expect", "unwrap", "panic"):
            for attr in attrs:
                with self.subTest(kind=kind, attr=attr):
                    visible = self._call(kind, "visible")
                    source = f"{attr}\nfn prod() {{ {visible}; }}\n"
                    result = self.scan("src/cfg_trivia.rs", source)
                    self.assertEqual(result.returncode, 1, result.stdout)
                    self.assertIn(visible, result.stdout)

    def test_cfg_real_test_predicate_with_comment_or_raw_string_is_kept(self):
        attrs = (
            "#[cfg(all(test, /* note */ unix))]",
            '#[cfg(all(test, custom = r#"a,b"#))]',
        )
        for kind in ("expect", "unwrap", "panic"):
            for attr in attrs:
                with self.subTest(kind=kind, attr=attr):
                    hidden = self._call(kind, "hidden")
                    visible = self._call(kind, "visible")
                    source = (
                        f"{attr}\n"
                        "mod tests {\n"
                        f"    fn t() {{ {hidden}; }}\n"
                        "}\n"
                        f"fn prod() {{ {visible}; }}\n"
                    )
                    result = self.scan("src/cfg_real_test.rs", source)
                    self._assert_rejected(result, kind)

    def test_unicode_line_separator_does_not_hide_following_production_call(self):
        # grep counts LF only. U+2028 and form feed must not insert a line.
        for kind in ("expect", "unwrap", "panic"):
            for separator in ("\u2028", "\f"):
                with self.subTest(kind=kind, separator=repr(separator)):
                    hidden = self._call(kind, "hidden")
                    visible = self._call(kind, "visible")
                    source = (
                        f'const S: &str = "a{separator}b";\n'
                        "#[cfg(test)]\n"
                        f"fn helper() {{ {hidden}; }}\n"
                        f"fn prod() {{ {visible}; }}\n"
                    )
                    result = self.scan("src/line_sep.rs", source)
                    self._assert_rejected(result, kind)

    def test_const_generic_brace_after_newline_or_comment_hides_test_call(self):
        signatures = (
            "fn helper() -> std::array::IntoIter<u8,\n{1}> {\n",
            "fn helper() -> std::array::IntoIter<u8, /* size */ {1}> {\n",
        )
        for kind in ("expect", "unwrap", "panic"):
            for signature in signatures:
                with self.subTest(kind=kind, signature=signature):
                    hidden = self._call(kind, "hidden")
                    source = (
                        "#[cfg(test)]\n"
                        f"{signature}"
                        f"    {hidden};\n"
                        "}\n"
                        "fn prod() {}\n"
                    )
                    result = self.scan("src/generic_break.rs", source)
                    self.assert_clean(result)
                    self.assertNotIn("hidden", result.stdout)

    def test_const_generic_brace_after_newline_or_comment_does_not_hide_production(self):
        signatures = (
            "fn helper() -> std::array::IntoIter<u8,\n{1}> {\n",
            "fn helper() -> std::array::IntoIter<u8, /* size */ {1}> {\n",
        )
        for kind in ("expect", "unwrap", "panic"):
            for signature in signatures:
                with self.subTest(kind=kind, signature=signature):
                    hidden = self._call(kind, "hidden")
                    visible = self._call(kind, "visible")
                    source = (
                        "#[cfg(test)]\n"
                        f"{signature}"
                        f"    {hidden};\n"
                        "}\n"
                        f"fn prod() {{ {visible}; }}\n"
                    )
                    result = self.scan("src/generic_break_prod.rs", source)
                    self._assert_rejected(result, kind)

    def test_bare_cr_in_block_comment_does_not_hide_production_call(self):
        # open() must not turn a bare CR into LF. grep still counts one line.
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

    def test_comment_before_generic_hides_test_call(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                source = (
                    "#[cfg(test)]\n"
                    "fn helper() -> std::array::IntoIter /* note */ <u8, {1}> {\n"
                    f"    {hidden};\n"
                    "    [0u8].into_iter()\n"
                    "}\n"
                    "fn prod() {}\n"
                )
                result = self.scan("src/generic_comment.rs", source)
                self.assert_clean(result)
                self.assertNotIn("hidden", result.stdout)

    def test_comment_before_generic_does_not_hide_production_call(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                visible = self._call(kind, "visible")
                source = (
                    "#[cfg(test)]\n"
                    "fn helper() -> std::array::IntoIter /* note */ <u8, {1}> {\n"
                    f"    {hidden};\n"
                    "    [0u8].into_iter()\n"
                    "}\n"
                    f"fn prod() {{ {visible}; }}\n"
                )
                result = self.scan("src/generic_comment_prod.rs", source)
                self._assert_rejected(result, kind)

    def test_cfg_test_literal_does_not_hide_next_element(self):
        # `1` never sets expr mode, so the comma must still end the item.
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                visible = self._call(kind, "visible")
                source = (
                    "fn prod() {\n"
                    "    let _ = [\n"
                    "        #[cfg(test)]\n"
                    "        1,\n"
                    f"        {visible},\n"
                    "    ];\n"
                    "}\n"
                )
                result = self.scan("src/literal_elem.rs", source)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(visible, result.stdout)

    def test_cfg_test_non_identifier_expr_is_accepted(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                source = (
                    "fn prod() {\n"
                    "    let _ = [\n"
                    "        #[cfg(test)]\n"
                    f"        ({hidden}),\n"
                    "        2,\n"
                    "    ];\n"
                    "}\n"
                )
                result = self.scan("src/literal_only.rs", source)
                self.assert_clean(result)
                self.assertNotIn("hidden", result.stdout)

    def test_return_type_macro_hides_test_call(self):
        for kind in ("expect", "unwrap", "panic"):
            for form in ("{}", "()"):
                with self.subTest(kind=kind, form=form):
                    hidden = self._call(kind, "hidden")
                    source = (
                        "macro_rules! unit { () => { () } }\n"
                        "#[cfg(test)]\n"
                        f"fn helper() -> unit!{form} {{\n"
                        f"    {hidden};\n"
                        "}\n"
                        "fn prod() {}\n"
                    )
                    result = self.scan("src/ret_macro.rs", source)
                    self.assert_clean(result)
                    self.assertNotIn("hidden", result.stdout)

    def test_return_type_macro_does_not_hide_production_call(self):
        for kind in ("expect", "unwrap", "panic"):
            for form in ("{}", "()"):
                with self.subTest(kind=kind, form=form):
                    hidden = self._call(kind, "hidden")
                    visible = self._call(kind, "visible")
                    source = (
                        "macro_rules! unit { () => { () } }\n"
                        "#[cfg(test)]\n"
                        f"fn helper() -> unit!{form} {{\n"
                        f"    {hidden};\n"
                        "}\n"
                        f"fn prod() {{ {visible}; }}\n"
                    )
                    result = self.scan("src/ret_macro_prod.rs", source)
                    self._assert_rejected(result, kind)

    def test_const_initializer_block_hides_test_call(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                source = (
                    "#[cfg(test)]\n"
                    f"const X: usize = {{0}} + {{ if false {{ {hidden}; }} 1 }};\n"
                )
                result = self.scan("src/const_init.rs", source)
                self.assert_clean(result)
                self.assertNotIn("hidden", result.stdout)

    def test_const_initializer_block_does_not_hide_production_call(self):
        for kind in ("expect", "unwrap", "panic"):
            with self.subTest(kind=kind):
                hidden = self._call(kind, "hidden")
                visible = self._call(kind, "visible")
                source = (
                    "#[cfg(test)]\n"
                    f"const X: usize = {{0}} + {{ if false {{ {hidden}; }} 1 }};\n"
                    f"fn prod() {{ {visible}; }}\n"
                )
                result = self.scan("src/const_init_prod.rs", source)
                self._assert_rejected(result, kind)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner", type=Path, default=SCANNER)
    args, unittest_args = parser.parse_known_args()
    SCANNER = args.scanner.resolve(strict=True)
    unittest.main(argv=[__file__, *unittest_args], verbosity=2)
