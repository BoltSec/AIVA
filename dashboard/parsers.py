"""Parse dependency manifests into Package lists.

Supports requirements.txt (PyPI) and package.json (npm).
Only pinned/explicit versions are scanned — ranges are normalised to a
concrete version where possible, otherwise skipped (and reported).
"""
from __future__ import annotations

import json
import re

from shared.models import Package

_REQ_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-]+)")
_NPM_RANGE = re.compile(r"^[\^~>=<\s]*")


def detect(filename: str) -> str:
    name = filename.lower()
    if name.endswith("package.json"):
        return "npm"
    if "requirements" in name or name.endswith(".txt"):
        return "pypi"
    raise ValueError(f"Unsupported manifest: {filename}")


def parse(filename: str, content: bytes) -> tuple[str, list[Package], list[str]]:
    """Return (ecosystem, packages, skipped_lines)."""
    eco = detect(filename)
    if eco == "npm":
        return ("npm", *_parse_npm(content))
    return ("PyPI", *_parse_requirements(content))


def _parse_requirements(content: bytes) -> tuple[list[Package], list[str]]:
    pkgs, skipped = [], []
    for raw in content.decode("utf-8", "replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ_RE.match(line)
        if m:
            pkgs.append(Package(ecosystem="PyPI", name=m.group(1).lower(),
                                version=m.group(2)))
        else:
            skipped.append(line)
    return pkgs, skipped


def _parse_npm(content: bytes) -> tuple[list[Package], list[str]]:
    data = json.loads(content.decode("utf-8", "replace"))
    pkgs, skipped = [], []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            ver = _NPM_RANGE.sub("", str(spec)).strip()
            if re.match(r"^\d+\.\d+", ver):
                pkgs.append(Package(ecosystem="npm", name=name, version=ver))
            else:
                skipped.append(f"{name}@{spec}")
    return pkgs, skipped
