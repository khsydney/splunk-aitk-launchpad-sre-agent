"""Minimal .env reader: KEY=VALUE lines, optional `export `, quotes, and inline ` # comments` on unquoted values.
Only fills names not already set. Values are never printed."""

from __future__ import annotations

import os
import pathlib


def parse_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        return None
    k, v = line.split("=", 1)
    k = k.strip().removeprefix("export ").strip()
    v = v.strip()
    if v[:1] in ("'", '"') and v[:1] in v[1:]:
        v = v[1:v.index(v[0], 1)]                  # quoted: keep everything inside the quotes, drop what follows
    else:
        v = v.split(" #", 1)[0].split("\t#", 1)[0].strip()   # unquoted: strip an inline comment
    return (k, v) if k and v else None


def load(paths) -> list[str]:
    loaded = []
    for p in paths:
        p = pathlib.Path(p)
        if not p.is_file():
            continue
        for line in p.read_text().splitlines():
            kv = parse_line(line)
            if kv and kv[0] not in os.environ:
                os.environ[kv[0]] = kv[1]
                loaded.append(kv[0])
    return loaded
