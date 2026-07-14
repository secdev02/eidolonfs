"""CSV metadata loader.

This keeps the same file-metadata approach used by the earlier EidolonFS
builds: a flat, line-oriented listing where each row declares one path, its
type, size, and timestamp, with parents listed before children. Here it is
formalized as a proper CSV with a header so it opens cleanly in any editor or
spreadsheet.

CSV columns
-----------
path         Absolute virtual path, POSIX style, for example /finance/q4.xlsx.
             The root "/" is implicit and does not need a row.
is_dir       1 for a directory, 0 for a file.
size         Declared size in bytes for files. Directories ignore this. The
             content synthesizer pads or truncates generated content to match,
             so the size an attacker sees on stat equals the bytes they can read.
mtime        Modification time as a Unix timestamp (seconds). Also used for
             atime and ctime unless you extend the schema.
mode         Octal permission bits, for example 0644 or 0600. Optional. Blank
             defaults to 0755 for directories and 0644 for files.
decoy_class  Free-form tag that drives alert priority and grouping, for example
             credential, financial, source, pii. Optional.
content_ref  Template key or seed-file path for synthesized content. Optional.
             Blank means synthesize by file extension.

Rules
-----
Lines beginning with # are comments. Blank lines are ignored. Parents must
appear before their children. Every intermediate directory must be declared
explicitly (the loader validates this and reports the first gap).
"""

import csv
import io
import stat as stat_module


DEFAULT_DIR_MODE = 0o755
DEFAULT_FILE_MODE = 0o644

_HEADER = ["path", "is_dir", "size", "mtime", "mode", "decoy_class", "content_ref"]


class LayoutError(Exception):
    """Raised when the CSV metadata is malformed or inconsistent."""


class Node:
    """One entry in the virtual filesystem."""

    __slots__ = (
        "path", "is_dir", "size", "mtime", "mode",
        "decoy_class", "content_ref", "children",
    )

    def __init__(self, path, is_dir, size, mtime, mode, decoy_class, content_ref):
        self.path = path
        self.is_dir = is_dir
        self.size = size
        self.mtime = mtime
        self.mode = mode
        self.decoy_class = decoy_class
        self.content_ref = content_ref
        # Child base names, populated for directories only.
        self.children = [] if is_dir else None


class Layout:
    """The whole virtual tree, indexed by path for constant-time lookup."""

    def __init__(self):
        self.nodes = {}
        # Seed the implicit root directory.
        root = Node("/", True, 0, 0, DEFAULT_DIR_MODE, "", "")
        self.nodes["/"] = root

    def get(self, path):
        return self.nodes.get(_normalize(path))

    def children_of(self, path):
        node = self.get(path)
        if node is None or not node.is_dir:
            return None
        return list(node.children)

    def _add(self, node):
        parent = _parent_of(node.path)
        parent_node = self.nodes.get(parent)
        if parent_node is None:
            raise LayoutError(
                "missing parent directory '" + parent
                + "' for '" + node.path + "' (declare parents before children)"
            )
        if not parent_node.is_dir:
            raise LayoutError(
                "parent '" + parent + "' of '" + node.path + "' is not a directory"
            )
        if node.path in self.nodes:
            raise LayoutError("duplicate path '" + node.path + "'")
        self.nodes[node.path] = node
        parent_node.children.append(_basename(node.path))


def load(source):
    """Load a Layout from a filesystem path or an open text stream."""
    if isinstance(source, str):
        with io.open(source, "r", encoding="utf-8", newline="") as handle:
            return _parse(handle)
    return _parse(source)


def _parse(handle):
    layout = Layout()
    # Strip comment and blank lines before handing rows to the CSV reader so
    # a stray # inside a quoted field is never mistaken for a comment.
    cleaned = []
    for raw in handle:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        cleaned.append(raw)

    if not cleaned:
        raise LayoutError("CSV metadata is empty")

    reader = csv.reader(cleaned)
    header = next(reader)
    header = [column.strip() for column in header]
    if header != _HEADER:
        raise LayoutError(
            "unexpected header. expected " + ",".join(_HEADER)
            + " but got " + ",".join(header)
        )

    line_number = 1
    for row in reader:
        line_number += 1
        if len(row) != len(_HEADER):
            raise LayoutError(
                "row " + str(line_number) + " has " + str(len(row))
                + " fields, expected " + str(len(_HEADER))
            )
        node = _row_to_node(row, line_number)
        layout._add(node)

    return layout


def _row_to_node(row, line_number):
    path_raw, is_dir_raw, size_raw, mtime_raw, mode_raw, decoy_class, content_ref = row

    raw = path_raw.strip()
    if not raw.startswith("/"):
        raise LayoutError("row " + str(line_number) + ": path must be absolute")
    path = _normalize(raw)

    is_dir = is_dir_raw.strip() in ("1", "true", "True", "yes")

    size = 0
    if not is_dir and size_raw.strip():
        try:
            size = int(size_raw.strip())
        except ValueError:
            raise LayoutError("row " + str(line_number) + ": size is not an integer")

    mtime = 0
    if mtime_raw.strip():
        try:
            mtime = int(float(mtime_raw.strip()))
        except ValueError:
            raise LayoutError("row " + str(line_number) + ": mtime is not a number")

    if mode_raw.strip():
        try:
            mode = int(mode_raw.strip(), 8)
        except ValueError:
            raise LayoutError("row " + str(line_number) + ": mode is not octal")
    else:
        mode = DEFAULT_DIR_MODE if is_dir else DEFAULT_FILE_MODE

    return Node(
        path=path,
        is_dir=is_dir,
        size=size,
        mtime=mtime,
        mode=mode,
        decoy_class=decoy_class.strip(),
        content_ref=content_ref.strip(),
    )


def full_mode(node):
    """Combine the file-type bits with the permission bits for getattr."""
    type_bits = stat_module.S_IFDIR if node.is_dir else stat_module.S_IFREG
    return type_bits | node.mode


def _normalize(path):
    if not path:
        return "/"
    # Collapse duplicate slashes and drop a trailing slash except for root.
    parts = [segment for segment in path.split("/") if segment]
    if not parts:
        return "/"
    return "/" + "/".join(parts)


def _parent_of(path):
    normalized = _normalize(path)
    if normalized == "/":
        return "/"
    index = normalized.rfind("/")
    if index <= 0:
        return "/"
    return normalized[:index]


def _basename(path):
    normalized = _normalize(path)
    return normalized.rsplit("/", 1)[-1]
