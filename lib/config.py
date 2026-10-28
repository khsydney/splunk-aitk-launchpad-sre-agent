"""Settings for the quick start: read `config.env` (repo root, git-ignored) into the environment without overriding
variables already set, then expose them. Missing required settings stop with a clear message."""
import os, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
_FILE = pathlib.Path(os.environ.get("SRE_CONFIG", ROOT / "config.env"))
if _FILE.exists():
    for line in _FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.split(" #", 1)[0].strip().strip('"').strip("'")
        os.environ.setdefault(k.strip(), os.path.expanduser(v))


def get(name, default=None, required=False):
    v = os.environ.get(name, default)
    if required and not v:
        sys.exit(f"missing setting {name}: set it in config.env (see config.env.example)")
    return v


def need(*names):
    missing = [n for n in names if not os.environ.get(n)]
    if missing:
        sys.exit("missing settings: " + ", ".join(missing) + " — set them in config.env (see config.env.example)")


def secret_from_file(var):
    """Read a secret from the file named by `var` (first line), never from the command line."""
    path = get(var, required=True)
    p = pathlib.Path(os.path.expanduser(path))
    if not p.exists():
        sys.exit(f"{var} points to {p}, which does not exist")
    return p.read_text().splitlines()[0].strip()
