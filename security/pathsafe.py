"""
Filesystem path safety.

Every route that touches a file under storage/instances/<folder>/... must
go through safe_join() so that no combination of folder name, sub-path,
or filename can ever escape the intended base directory (classic path
traversal / zip-slip prevention), and through a symlink check so a
crafted symlink inside an instance can't be used to read/write outside
of it either.
"""
import os


class UnsafePathError(Exception):
    pass


def safe_join(base_dir: str, *parts: str) -> str:
    """Join path parts under base_dir, refusing anything that would
    resolve outside of it (../, absolute paths, NUL bytes, symlink
    escapes, drive letters, etc.). Raises UnsafePathError on violation.
    """
    base_real = os.path.realpath(base_dir)
    candidate = base_real
    for part in parts:
        if part is None:
            continue
        part = str(part)
        if "\x00" in part:
            raise UnsafePathError("null byte in path")
        # Reject absolute paths / drive letters / home-dir expansion outright
        if os.path.isabs(part) or part.startswith("~"):
            raise UnsafePathError(f"absolute path not allowed: {part}")
        candidate = os.path.join(candidate, part)

    normalized = os.path.normpath(candidate)
    if normalized != base_real and not normalized.startswith(base_real + os.sep):
        raise UnsafePathError(f"path escapes base directory: {normalized}")

    # If the path exists, also resolve symlinks and re-check containment,
    # so a symlink planted inside an instance can't point outside it.
    if os.path.exists(normalized):
        real = os.path.realpath(normalized)
        if real != base_real and not real.startswith(base_real + os.sep):
            raise UnsafePathError(f"symlink escapes base directory: {normalized}")

    return normalized


def safe_filename_component(name: str) -> bool:
    """True if `name` is safe to use as a single path *component*
    (no separators, no traversal, not empty)."""
    if not name or name in (".", ".."):
        return False
    if "/" in name or "\\" in name or "\x00" in name:
        return False
    return True
