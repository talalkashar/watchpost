"""Wire representations of the public UI files."""
import gzip
import hashlib
from functools import lru_cache

# Preserve the cascade from the individual source sheets.
CONSOLE_STYLES = ("style.css", "views.css", "glass.css", "orbit.css", "declutter.css", "graph.css")


def public_file(root, name):
    # Select each component from the directory itself; resolve symlinks before descending.
    current = root
    for part in name.split("/"):
        if not current.is_dir():
            return None
        entry = next((child for child in current.iterdir() if child.name == part), None)
        if entry is None:
            return None
        current = entry.resolve()
        if root not in current.parents:
            return None
    return current if current.is_file() else None


def accepts_gzip(header):
    qualities = {}
    for item in header.lower().split(","):
        name, _, params = item.strip().partition(";")
        name = name.strip()
        if name not in ("gzip", "*", "identity"):
            continue
        quality = 1.0
        if params:
            key, _, value = params.strip().partition("=")
            try:
                quality = float(value) if key.strip() == "q" else 0
            except ValueError:
                quality = 0
        qualities[name] = quality if 0 <= quality <= 1 else 0
    weight = qualities.get("gzip", qualities.get("*", 0))
    return weight > 0 and weight >= qualities.get("identity", 0)


def representation(paths, compress):
    # Edits and atomic replacements invalidate the cached bytes, including edits to bundle inputs.
    inputs = []
    for path in paths:
        stat = path.stat()
        inputs.append((path, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size))
    return _representation(tuple(inputs), compress)


@lru_cache(maxsize=64)
def _representation(inputs, compress):
    body = b"\n".join(path.read_bytes() for path, *_ in inputs)
    if compress:
        body = gzip.compress(body, compresslevel=6, mtime=0)
    etag = '"' + hashlib.sha256(body).hexdigest() + '"'
    return body, etag
