"""EidolonFS: a cross-platform FUSE honeypot filesystem.

EidolonFS projects a tree of synthetic decoy files (fake credentials, keys,
financial documents) described by a CSV metadata file. Directory listing and
stat calls are served silently. Any explicit open, read, or copy of a decoy
file raises a verbose, attributed alert event.

Public entry points live in eidolonfs.cli. The FUSE operations class lives in
eidolonfs.vfs. The CSV metadata loader lives in eidolonfs.layout.
"""

__version__ = "2.0.0"

__all__ = ["__version__"]
