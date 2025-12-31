# Review Staged Changes

Review the currently staged changes (`git diff --cached`) for this project.

## Review Process

Use sub-agents in parallel to check the following aspects:

### 1. Code Style & Conventions
Reference: `doc/developers/style.rst` and `.clang-format`

Check for:
- `bf_` prefix for all public symbols, `_bf_` for static/internal
- Cleanup attributes: `_free_bf_*_`, `_cleanup_free_`, `_clean_bf_*_`
- 80-column limit violations
- Brace placement: new line for functions/structs, same line for control flow
- Comment style: `//` for single-line, `/* */` for multi-line (aligned asterisks)
- Doxygen: `@param`, `@return`, no `@brief`, use backticks for symbol references

Run `clang-format --style=file:.clang-format --dry-run` on changed files to detect formatting issues.

### 2. Memory Safety & Security
Check for:
- Buffer overflows and bounds checking issues
- Use-after-free patterns
- Missing cleanup attributes on heap allocations
- Potential NULL pointer dereferences
- Resource leaks (file descriptors, memory)

### 3. Test Coverage
Check for:
- New functions in `src/libbpfilter/` must have corresponding unit tests in `tests/unit/`
- Changes to existing functions should not break test expectations
- E2E test coverage for user-facing changes

## Output Format

Group findings by severity:
1. **Regressions**: Issues that must be fixed before commit
2. **Suggestions**: Improvements that could be made
3. **Questions**: Clarifications needed about the code

Use call chains for clarity: `funcA()`->`funcB()`

Reference functions by name, not line numbers.
