"""Synthetic decoy content.

Every byte an attacker reads out of EidolonFS is generated here, never taken
from a real file unless the operator points content_ref at a seed file they
have chosen to expose. Content is deterministic per path so repeated reads and
partial reads stay consistent, and it is padded or truncated to the size the
CSV declared, so what stat reports equals what read returns.

The generated payloads are intentionally plausible bait (credentials, keys,
config, tabular data) but each carries a quiet marker that it is a EidolonFS
decoy. That marker is useful in forensics and harmless to detection: by the
time anything reads far enough to see it, the open and read have already been
alerted on.
"""

import hashlib
import io
import os


_MARKER = "EidolonFS synthetic decoy. Access is logged."


def _seed_bytes(path, length):
    """Deterministic filler derived from the path, for realistic-looking blobs."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        digest = hashlib.sha256((path + ":" + str(counter)).encode("utf-8")).digest()
        out.extend(digest)
        counter += 1
    return bytes(out[:length])


def _template_txt(path):
    return (
        "CONFIDENTIAL\n"
        "This document contains sensitive information.\n"
        "Access is monitored and logged. Authorised personnel only.\n"
        "\n"
        + _MARKER + "\n"
    ).encode("utf-8")


def _template_csv(path):
    return (
        "id,name,email,department,access_level\n"
        "1,admin,admin@example.com,IT,superadmin\n"
        "2,deploy,deploy@example.com,Engineering,admin\n"
        "3,backup,backup@example.com,Operations,read-only\n"
        "# " + _MARKER + "\n"
    ).encode("utf-8")


def _template_json(path):
    return (
        "{\n"
        '  "synthetic": true,\n'
        '  "generator": "EidolonFS",\n'
        '  "note": "This is a honeypot file. Access has been logged."\n'
        "}\n"
    ).encode("utf-8")


def _template_pem(path):
    # A syntactically shaped but non-functional key block. The base64 body is
    # deterministic filler, not a real key.
    body = _seed_bytes(path, 384)
    import base64
    encoded = base64.encodebytes(body).decode("ascii").strip()
    lines = ["-----BEGIN PRIVATE KEY-----"]
    lines.extend(encoded.splitlines())
    lines.append("-----END PRIVATE KEY-----")
    lines.append("# " + _MARKER)
    return ("\n".join(lines) + "\n").encode("utf-8")


def _template_env(path):
    return (
        "# environment configuration\n"
        "AWS_ACCESS_KEY_ID=AKIA" + _seed_bytes(path, 8).hex()[:16].upper() + "\n"
        "AWS_SECRET_ACCESS_KEY=" + _seed_bytes(path + ":s", 20).hex()[:40] + "\n"
        "DB_PASSWORD=" + _seed_bytes(path + ":d", 12).hex()[:24] + "\n"
        "# " + _MARKER + "\n"
    ).encode("utf-8")


def _template_generic(path):
    return (_MARKER + "\n").encode("utf-8")


# Explicit template keys usable in the content_ref column.
_TEMPLATES = {
    "txt": _template_txt,
    "csv": _template_csv,
    "json": _template_json,
    "pem": _template_pem,
    "key": _template_pem,
    "env": _template_env,
    "creds": _template_env,
    "generic": _template_generic,
}

# Extension to template mapping used when content_ref is blank.
_EXT_TEMPLATES = {
    ".txt": "txt",
    ".log": "txt",
    ".md": "txt",
    ".csv": "csv",
    ".tsv": "csv",
    ".json": "json",
    ".yaml": "json",
    ".yml": "json",
    ".pem": "pem",
    ".key": "pem",
    ".env": "env",
}


class ContentStore:
    """Generates and caches decoy content, sized to the declared file size."""

    def __init__(self, seed_root=None, cache_limit=1024):
        # seed_root, if set, is a read-only directory of real files an operator
        # deliberately exposes. content_ref may reference a relative path under
        # it. This is opt-in; the default is fully synthetic.
        self.seed_root = seed_root
        self._cache = {}
        self._cache_limit = cache_limit

    def render(self, node):
        """Return the full byte content for a file node."""
        cached = self._cache.get(node.path)
        if cached is not None:
            return cached

        data = self._build(node)
        data = self._fit(data, node.size)

        if len(self._cache) < self._cache_limit:
            self._cache[node.path] = data
        return data

    def _build(self, node):
        ref = node.content_ref

        # A seed file reference, only honored when a seed_root is configured.
        if ref and self.seed_root:
            candidate = os.path.normpath(os.path.join(self.seed_root, ref))
            root = os.path.normpath(self.seed_root)
            if candidate.startswith(root) and os.path.isfile(candidate):
                with io.open(candidate, "rb") as handle:
                    return handle.read()

        # An explicit template key.
        if ref in _TEMPLATES:
            return _TEMPLATES[ref](node.path)

        # Fall back to the file extension.
        _, ext = os.path.splitext(node.path.lower())
        template_key = _EXT_TEMPLATES.get(ext, "generic")
        return _TEMPLATES[template_key](node.path)

    def _fit(self, data, declared_size):
        """Pad or truncate content so its length equals the declared size."""
        if declared_size <= 0:
            return data
        if len(data) == declared_size:
            return data
        if len(data) > declared_size:
            return data[:declared_size]
        # Pad with deterministic filler so the tail is not just zero bytes.
        pad = _seed_bytes("pad:" + str(declared_size), declared_size - len(data))
        return data + pad
