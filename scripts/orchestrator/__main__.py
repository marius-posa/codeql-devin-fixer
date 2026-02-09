"""Allow running the orchestrator as ``python scripts/orchestrator`` or
``python -m scripts.orchestrator``.
"""

import sys

from scripts.orchestrator.cli import main

sys.exit(main())
