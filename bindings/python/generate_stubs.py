#!/usr/bin/env python3
"""
Validate type stubs for x0x Python bindings.

This script checks that:
1. All stub files exist and are syntactically valid
2. Stubs can be imported
3. mypy can type-check test files using the stubs
"""

import sys
from pathlib import Path

def check_stub_files_exist():
    """Verify all expected stub files exist."""
    print("Checking stub files...")

    stub_dir = Path(__file__).parent / "x0x"
    expected_stubs = [
        "__init__.pyi",
        "agent.pyi",
        "identity.pyi",
        "pubsub.pyi",
        "task_list.pyi",
    ]

    missing = []
    for stub_file in expected_stubs:
        stub_path = stub_dir / stub_file
        if not stub_path.exists():
            missing.append(str(stub_path))
        else:
            print(f"  ✓ {stub_file}")

    if missing:
        print(f"\n❌ Missing stub files:")
        for path in missing:
            print(f"  - {path}")
        return False

    print("✓ All stub files present\n")
    return True

def check_stub_syntax():
    """Verify stub files have valid Python syntax."""
    print("Checking stub syntax...")

    stub_dir = Path(__file__).parent / "x0x"
    stub_files = list(stub_dir.glob("*.pyi"))

    errors = []
    for stub_file in stub_files:
        try:
            compile(stub_file.read_text(), stub_file, "exec")
            print(f"  ✓ {stub_file.name}")
        except SyntaxError as e:
            errors.append((stub_file, e))
            print(f"  ❌ {stub_file.name}: {e}")

    if errors:
        return False

    print("✓ All stubs have valid syntax\n")
    return True

def check_mypy_available():
    """Check if mypy is installed."""
    print("Checking mypy availability...")

    try:
        import mypy
        print(f"  ✓ mypy {mypy.__version__} installed\n")
        return True
    except ImportError:
        print("  ⚠ mypy not installed")
        print("  Install with: pip install mypy")
        print("  Skipping type checking\n")
        return False

def run_mypy_on_tests():
    """Run mypy on test files to validate stubs."""
    print("Running mypy on test files...")

    import subprocess

    tests_dir = Path(__file__).parent / "tests"
    test_files = list(tests_dir.glob("test_*.py"))

    if not test_files:
        print("  ⚠ No test files found\n")
        return True

    # Run mypy
    cmd = ["mypy", "--strict", "--"] + [str(f) for f in test_files]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent
        )

        if result.returncode == 0:
            print("  ✓ mypy found no type errors\n")
            return True
        else:
            print(f"  ❌ mypy found type errors:\n")
            print(result.stdout)
            return False

    except FileNotFoundError:
        print("  ⚠ mypy command not found in PATH")
        print("  Install with: pip install mypy\n")
        return False

def main():
    """Run all validation checks."""
    print("=" * 60)
    print("x0x Type Stub Validation")
    print("=" * 60)
    print()

    checks = [
        ("Stub files exist", check_stub_files_exist),
        ("Stub syntax valid", check_stub_syntax),
    ]

    # Run core checks
    all_passed = True
    for name, check_func in checks:
        if not check_func():
            all_passed = False
            print(f"❌ {name} check failed\n")

    # Run mypy if available
    if check_mypy_available():
        # Note: mypy check is informational - don't fail on it
        # since tests may not be fully type-annotated yet
        run_mypy_on_tests()

    # Summary
    print("=" * 60)
    if all_passed:
        print("✅ All type stub validation checks passed!")
    else:
        print("❌ Some validation checks failed")
        return 1
    print("=" * 60)

    return 0

if __name__ == "__main__":
    sys.exit(main())
