"""safepaths.py - the few file-system rules every builder in the family follows, in one place (used by the DKG builders and the training runs).

Third-party repos and their manifests are UNTRUSTED input: a manifest row, a repo name or a symlink can point outside the folder a builder is meant to stay in.
  safe_name(x)             a repo name that is one plain path component (no separators, no '..', no control characters)
  contained(root, *parts)  the resolved path, refused unless it stays inside root after symlinks are resolved
  read_capped(path, limit) read a file, refusing one over the size limit (a hostile repo can hold a huge file)
  atomic_write(path, text) write beside the target and swap in, so a crash never leaves a half-written file"""
import os
import re
import tempfile

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._ +@-]{0,199}")


class PathRefused(ValueError):
    pass


_WIN_DEVICE = re.compile(r"(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$")


def safe_name(name):
    if (not isinstance(name, str) or not _NAME.fullmatch(name) or ".." in name or name.endswith((".", " ")) or _WIN_DEVICE.match(name)):
        raise PathRefused(f"{name!r} is not a plain name (letters, digits, . _ - + @ space; no separators, no '..')")
    return name


def contained(root, *parts):
    root_real = os.path.realpath(root)
    for p in parts:
        if not isinstance(p, str) or "\x00" in p:
            raise PathRefused("path part must be text without NUL")
    target = os.path.realpath(os.path.join(root_real, *parts))
    try:
        inside = os.path.commonpath([root_real, target]) == root_real
    except ValueError:                                    # different drives on Windows
        inside = False
    if not inside:
        raise PathRefused(f"{os.path.join(*parts)!r} resolves outside {root}")
    return target


def read_capped(path, limit):
    size = os.path.getsize(path)
    if size > limit:
        raise PathRefused(f"{path} is {size} bytes, over the {limit} limit")
    chunks, total = [], 0
    with open(path, "rb") as fh:                                  # read in chunks: read(limit + 1) reserves limit bytes up front, even for a tiny file
        while True:
            chunk = fh.read(min(1 << 20, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise PathRefused(f"{path} grew past the {limit} limit while being read")
    return b"".join(chunks)


def atomic_write(path, text, newline="\n"):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline=newline) as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass  # reviewed: the temp file may already be gone; the original error is re-raised
        raise
