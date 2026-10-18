"""merkle.py - batch many commitment hashes into one root so a cheap public witness can anchor thousands of
commitments with a single small write. Domain-separated (leaf 0x00 / node 0x01); an odd node is carried up
unchanged, never duplicated."""
import hashlib


def _leaf(b: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + b).digest()


def _node(l: bytes, r: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + l + r).digest()


def root(leaves) -> bytes:
    if not leaves:
        raise ValueError("no leaves")
    level = [_leaf(x) for x in leaves]
    while len(level) > 1:
        nxt = [_node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def proof(leaves, index: int):
    """List of (side, sibling_hash) from leaf to root. side is 'L' or 'R' (where the sibling sits)."""
    if not 0 <= index < len(leaves):
        raise ValueError("leaf index out of range")
    level = [_leaf(x) for x in leaves]
    out, i = [], index
    while len(level) > 1:
        if i % 2 == 1:
            out.append(("L", level[i - 1]))
        elif i + 1 < len(level):
            out.append(("R", level[i + 1]))
        nxt = [_node(level[j], level[j + 1]) for j in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level, i = nxt, i // 2
    return out


def verify_proof(leaf: bytes, path, expected_root: bytes) -> bool:
    h = _leaf(leaf)
    for side, sib in path:
        if side not in ("L", "R") or not isinstance(sib, (bytes, bytearray)) or len(sib) != 32:
            return False
        h = _node(sib, h) if side == "L" else _node(h, sib)
    return h == expected_root
