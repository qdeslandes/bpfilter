# Pre-Commit Check

Validate staged changes before committing. This is a fast validation that runs essential checks.

## Validation Steps

### 1. Check for Staged Changes
```bash
git diff --cached --name-only
```

If no staged changes, inform the user and exit.

### 2. Style Check (Parallel)

Run on all staged `.c` and `.h` files:
```bash
clang-format --style=file:.clang-format --dry-run <files>
```

If style issues found, suggest:
```bash
make -C build fixstyle
```

### 3. Build Validation
```bash
make -C build
```

Must exit with code 0.

### 4. Test Suite
```bash
make -C build test
```

Must exit with code 0. This runs:
- Unit tests
- Integration tests
- E2E tests
- Linter checks (clang-tidy, shellcheck, iwyu)

## Output

### Pass
```
✓ All pre-commit checks passed. Ready to commit.
```

### Fail
List each failure with:
- What failed
- How to fix it
- Command to run for auto-fix (if available)

Example:
```
✗ Style check failed

Files with formatting issues:
  - src/libbpfilter/foo.c

Fix with: make -C build fixstyle
```
