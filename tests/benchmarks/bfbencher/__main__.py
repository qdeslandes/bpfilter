"""Entry point for ``python -m bfbencher`` and ``python tests/benchmarks/bfbencher``."""

import sys
from pathlib import Path

# In script-directory mode Python puts the package dir itself on sys.path[0],
# not its parent, so `import bfbencher` does not resolve. Fix that up before
# loading the package. In `-m` mode __package__ is set and this is skipped.
if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bfbencher import main  # noqa: E402

main()
