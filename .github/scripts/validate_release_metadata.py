#!/usr/bin/env python3

import argparse
import fnmatch
import json
import re
import subprocess
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[2]
DEFAULT_POLICY_PATH = REPO_ROOT / ".github" / "release-metadata-policy.json"
SEMVER_PATTERN = re.compile(r"(?<![\d.])v?\d+\.\d+\.\d+(?![\d.])")


class ValidationState:
    def __init__(self):
        self.failures = []
        self.warnings = []

    def add(self, level, message, file_path=None, line_number=None):
        finding = {
            "message": message,
            "file": file_path,
            "line": line_number,
        }
        if level == "blocking":
            self.failures.append(finding)
        else:
            self.warnings.append(finding)

    def emit(self):
        for finding in self.failures:
            print(format_finding("error", finding))
        for finding in self.warnings:
            print(format_finding("warning", finding))


def format_finding(kind, finding):
    message = finding["message"]
    file_path = finding["file"]
    line_number = finding["line"]

    if file_path is None:
        return f"{kind.upper()}: {message}"

    if line_number is None:
        return f"::{kind} file={file_path}::{message}"

    return f"::{kind} file={file_path},line={line_number}::{message}"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Validate release metadata consistency"
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=["pull_request", "push_main", "release_tag"],
        help="Validation mode",
    )
    parser.add_argument(
        "--base-sha",
        help="Base commit SHA used to determine changed files for pull request mode",
    )
    parser.add_argument(
        "--tag",
        help="Release tag to compare against metadata in release_tag mode",
    )
    parser.add_argument(
        "--policy",
        default=str(DEFAULT_POLICY_PATH),
        help="Path to the JSON policy file",
    )
    return parser.parse_args()


def run_git(*args):
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def load_policy(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def normalize_tag(tag_name):
    if not tag_name:
        return None
    return tag_name[1:] if tag_name.startswith("v") else tag_name


def relative_path(path):
    return str(path.relative_to(REPO_ROOT)).replace("\\", "/")


def path_matches(path_str, pattern):
    return fnmatch.fnmatchcase(path_str, pattern)


def is_excluded(path_str, exclude_patterns):
    return any(path_matches(path_str, pattern) for pattern in exclude_patterns)


def get_changed_files(base_sha):
    committed = set(
        filter(None, run_git("diff", "--name-only", f"{base_sha}...HEAD").splitlines())
    )
    working_tree = set(
        filter(None, run_git("diff", "--name-only", "HEAD").splitlines())
    )
    untracked = set(
        filter(None, run_git("ls-files", "--others", "--exclude-standard").splitlines())
    )
    return sorted(committed | working_tree | untracked)


def expand_inputs(patterns, exclude_patterns):
    expanded = []
    for pattern in patterns:
        matches = (
            sorted(REPO_ROOT.glob(pattern))
            if any(token in pattern for token in "*?[")
            else [REPO_ROOT / pattern]
        )
        for match in matches:
            if not match.is_file():
                continue
            rel_path = relative_path(match)
            if is_excluded(rel_path, exclude_patterns):
                continue
            expanded.append(rel_path)
    return sorted(dict.fromkeys(expanded))


def select_rule_files(rule, mode, changed_files, policy):
    inputs = rule.get("inputs", [])
    exclude_patterns = policy.get("exclude", [])
    if mode != "pull_request":
        return expand_inputs(inputs, exclude_patterns)

    changed_matches = [
        path
        for path in changed_files
        if not is_excluded(path, exclude_patterns)
        and any(path_matches(path, pattern) for pattern in inputs)
    ]
    if changed_matches:
        return sorted(dict.fromkeys(changed_matches))

    return expand_inputs(inputs, exclude_patterns)


def should_run_rule(rule, mode, changed_files, policy):
    behavior = rule["modes"][mode]
    if behavior == "always":
        return True
    if behavior != "changed_only":
        raise ValueError(f"Unsupported rule mode behavior: {behavior}")

    triggers = list(rule.get("inputs", [])) + list(policy.get("global_triggers", []))
    return any(
        any(path_matches(path, pattern) for pattern in triggers)
        for path in changed_files
    )


def read_text(path_str):
    return (REPO_ROOT / path_str).read_text(encoding="utf-8")


def extract_skill_frontmatter(path_str):
    text = read_text(path_str)
    match = re.search(r"\A---\n(.*?)\n---(?:\n|$)", text, re.MULTILINE | re.DOTALL)
    if not match:
        raise ValueError(f"Could not parse frontmatter in {path_str}")
    return match.group(1)


def extract_skill_version(path_str):
    frontmatter = extract_skill_frontmatter(path_str)
    match = re.search(r"^version:\s*([^\n]+)$", frontmatter, re.MULTILINE)
    if not match:
        raise ValueError(f"Could not find version in {path_str}")
    return match.group(1).strip()


def extract_cargo_version(path_str):
    text = read_text(path_str)
    package_match = re.search(
        r"^\[package\]\n(.*?)(?=^\[|\Z)", text, re.MULTILINE | re.DOTALL
    )
    if not package_match:
        raise ValueError(f"Could not find [package] section in {path_str}")
    version_match = re.search(
        r'^version\s*=\s*"([^"]+)"\s*$', package_match.group(1), re.MULTILINE
    )
    if not version_match:
        raise ValueError(f"Could not find package version in {path_str}")
    return version_match.group(1)


def parse_inline_bins(value):
    text = value.strip()
    if not text.startswith("[") or not text.endswith("]"):
        raise ValueError(f"Expected inline list, got: {value}")
    items = []
    inner = text[1:-1].strip()
    if not inner:
        return items
    for part in inner.split(","):
        item = part.strip().strip('"').strip("'")
        if item:
            items.append(item)
    return items


def extract_openclaw_entries(path_str):
    # This frontmatter parser intentionally matches the current SKILL.md layout:
    # install entries use the existing indentation style and inline bins lists.
    frontmatter = extract_skill_frontmatter(path_str)
    entries = []
    current = None
    in_install = False
    install_indent = None

    for line in frontmatter.splitlines():
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))

        if stripped == "install:" and indent >= 4:
            in_install = True
            install_indent = indent
            current = None
            continue

        if not in_install:
            continue

        if stripped and indent <= install_indent:
            if current:
                entries.append(current)
            break

        if stripped.startswith("- kind:"):
            if current:
                entries.append(current)
            current = {}
            continue

        if current is None:
            continue

        if stripped.startswith("url:"):
            current["url"] = stripped.split(":", 1)[1].strip().strip('"')
        elif stripped.startswith("bins:"):
            current["bins"] = parse_inline_bins(stripped.split(":", 1)[1].strip())

    if in_install and current and current not in entries:
        entries.append(current)

    return entries


def extract_shell_loop_bins(path_str):
    text = read_text(path_str)
    match = re.search(r"for bin in ([^;]+); do", text)
    if not match:
        raise ValueError(f"Could not find install loop in {path_str}")
    return [item for item in match.group(1).split() if item]


def extract_step_run_block(path_str, step_name):
    lines = read_text(path_str).splitlines()

    for index, line in enumerate(lines):
        if line.strip() != f"- name: {step_name}":
            continue

        step_indent = len(line) - len(line.lstrip(" "))
        run_indent = None

        for next_index in range(index + 1, len(lines)):
            next_line = lines[next_index]
            stripped = next_line.strip()
            indent = len(next_line) - len(next_line.lstrip(" "))

            if stripped.startswith("- name:") and indent == step_indent:
                break

            if stripped == "run: |" and indent > step_indent:
                run_indent = indent
                block = []

                for body_index in range(next_index + 1, len(lines)):
                    body_line = lines[body_index]
                    body_stripped = body_line.strip()
                    body_indent = len(body_line) - len(body_line.lstrip(" "))

                    if body_stripped and body_indent <= run_indent:
                        break

                    if body_line.startswith(" " * (run_indent + 2)):
                        block.append(body_line[run_indent + 2 :])
                    elif not body_stripped:
                        block.append("")

                return "\n".join(block)

        raise ValueError(
            f"Could not find run block for workflow step {step_name!r} in {path_str}"
        )

    raise ValueError(f"Could not find workflow step {step_name!r} in {path_str}")


def extract_release_unix_bins(path_str):
    run_block = extract_step_run_block(path_str, "Package (tar.gz)")
    match = re.search(r"for bin in ([^;]+); do", run_block)
    if not match:
        raise ValueError(
            f"Could not find packaged unix binaries in Package (tar.gz) step of {path_str}"
        )
    return [item for item in match.group(1).split() if item]


def extract_release_windows_bins(path_str):
    text = read_text(path_str)
    bins = []
    for candidate in ["x0xd.exe", "x0x.exe"]:
        if candidate in text:
            bins.append(candidate)
    if len(bins) != 2:
        raise ValueError(f"Could not find packaged windows binaries in {path_str}")
    return bins


def validate_version_sync(rule, state, tag_version=None):
    skill_path, cargo_path = rule["inputs"]
    skill_version = extract_skill_version(skill_path)
    cargo_version = extract_cargo_version(cargo_path)

    if skill_version != cargo_version:
        state.add(
            rule["level"],
            f"SKILL.md version {skill_version} does not match Cargo.toml version {cargo_version}",
            skill_path,
        )

    if tag_version and skill_version != tag_version:
        state.add(
            rule["level"],
            f"SKILL.md version {skill_version} does not match release tag v{tag_version}",
            skill_path,
        )

    if tag_version and cargo_version != tag_version:
        state.add(
            rule["level"],
            f"Cargo.toml version {cargo_version} does not match release tag v{tag_version}",
            cargo_path,
        )


def validate_openclaw_bins(rule, state):
    skill_path, install_script_path, release_workflow_path = rule["inputs"]
    expected_unix = rule["expected_bins"]["unix"]
    expected_windows = rule["expected_bins"]["windows"]

    for entry in extract_openclaw_entries(skill_path):
        url = entry.get("url", "")
        bins = entry.get("bins", [])
        expected = expected_windows if "windows" in url else expected_unix
        if bins != expected:
            state.add(
                rule["level"],
                f"OpenClaw install entry for {url} declares bins {bins}, expected {expected}",
                skill_path,
            )

    install_bins = extract_shell_loop_bins(install_script_path)
    if install_bins != expected_unix:
        state.add(
            rule["level"],
            f"Installer script installs bins {install_bins}, expected {expected_unix}",
            install_script_path,
        )

    release_unix_bins = extract_release_unix_bins(release_workflow_path)
    if release_unix_bins != expected_unix:
        state.add(
            rule["level"],
            f"Release workflow packages unix bins {release_unix_bins}, expected {expected_unix}",
            release_workflow_path,
        )

    release_windows_bins = extract_release_windows_bins(release_workflow_path)
    if release_windows_bins != expected_windows:
        state.add(
            rule["level"],
            f"Release workflow packages windows bins {release_windows_bins}, expected {expected_windows}",
            release_workflow_path,
        )


def validate_current_release_docs(rule, mode, changed_files, policy, state):
    for path_str in select_rule_files(rule, mode, changed_files, policy):
        lines = read_text(path_str).splitlines()
        for index, line in enumerate(lines, start=1):
            if SEMVER_PATTERN.search(line):
                state.add(
                    rule["level"],
                    f"Current-release docs should avoid hardcoded semver here: {line.strip()}",
                    path_str,
                    index,
                )


def main():
    args = parse_args()
    policy = load_policy(args.policy)
    state = ValidationState()
    changed_files = []

    if args.mode == "pull_request":
        if not args.base_sha:
            raise SystemExit("--base-sha is required in pull_request mode")
        changed_files = get_changed_files(args.base_sha)
        print(
            f"Changed files for pull_request mode: {', '.join(changed_files) if changed_files else '(none)'}"
        )

    tag_version = None
    if args.mode == "release_tag":
        if not args.tag:
            raise SystemExit("--tag is required in release_tag mode")
        tag_version = normalize_tag(args.tag)
        print(f"Release tag version: {tag_version}")

    for rule_name, rule in policy["rules"].items():
        if not should_run_rule(rule, args.mode, changed_files, policy):
            continue

        print(f"Running {rule_name} ({rule['kind']})")

        if rule["kind"] == "version_sync":
            validate_version_sync(rule, state, tag_version=tag_version)
        elif rule["kind"] == "openclaw_bins":
            validate_openclaw_bins(rule, state)
        elif rule["kind"] == "current_release_docs":
            validate_current_release_docs(rule, args.mode, changed_files, policy, state)
        else:
            raise SystemExit(f"Unsupported rule kind: {rule['kind']}")

    state.emit()

    if state.failures:
        print(f"Validation failed with {len(state.failures)} blocking issue(s)")
        raise SystemExit(1)

    if state.warnings:
        print(f"Validation passed with {len(state.warnings)} warning(s)")
    else:
        print("Validation passed with no issues")


if __name__ == "__main__":
    main()
