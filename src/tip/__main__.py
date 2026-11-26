"""Allow `python -m tip` as an alias for the `tip` command."""

from .cli import main

raise SystemExit(main())
