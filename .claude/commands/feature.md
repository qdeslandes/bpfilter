# Implement Feature

Implement a new feature or enhancement for this project.

**Usage**: `/project:feature <DESCRIPTION>`

## Process

### 1. Understanding Phase

Before writing code:
- Search the codebase for related functionality
- Identify files that will need modification
- Check for existing patterns to follow
- Review `doc/developers/style.rst` for conventions

### 2. Planning Phase

Create a plan covering:
- Files to modify or create
- New functions needed (with `bf_` prefix)
- Test coverage requirements
- Any new dependencies

### 3. Implementation Phase

Follow these conventions:
- Use `bf_` prefix for public symbols, `_bf_` for static
- Use cleanup attributes for resource management
- Keep functions focused and small
- Add Doxygen comments for non-trivial functions

### 4. Testing Phase

For changes in:
- `src/libbpfilter/`: Add unit tests in `tests/unit/`
- `src/bpfilter/`: Consider integration tests
- User-facing changes: Add E2E tests in `tests/e2e/`

### 5. Validation Phase

Run the full test suite:
```bash
make -C build test
```

Must exit with code 0.

### 6. Self-Review

Before completing, run `/project:review` on your changes.

## Commit Message Format

Use: `component: subcomponent: description`

Components:
- `daemon`: src/bpfilter
- `lib`: src/libbpfilter
- `cli`: src/bfcli
- `build`: CMake
- `tests`: test infrastructure
- `doc`: documentation
