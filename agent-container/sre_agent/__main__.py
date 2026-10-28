"""Entry point. Loads unset names from the repo-root .env and services/sre-agent/.env (both git-ignored), e.g.
ANTHROPIC_API_KEY, before any module reads the environment. Values are never printed."""

import pathlib

from .envfile import load

_HERE = pathlib.Path(__file__).resolve().parent
load([_HERE.parent.parent.parent / ".env", _HERE.parent / ".env"])

from .cli import main  # noqa: E402

main()
