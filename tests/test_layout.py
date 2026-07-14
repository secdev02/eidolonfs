"""Tests for the CSV metadata parser."""

import io
import stat as stat_module

import pytest

from eidolonfs import layout as layout_module


def _load(text):
    return layout_module.load(io.StringIO(text))


VALID = """\
path,is_dir,size,mtime,mode,decoy_class,content_ref
/secrets,1,,1704067200,0700,,
/secrets/id_rsa,0,2048,1704067200,0600,credential,pem
/secrets/note.txt,0,,1704067200,,,
/pub,1,,1704067200,,,
"""


def test_loads_tree_and_indexes_paths():
    layout = _load(VALID)
    # root plus four declared nodes
    assert len(layout.nodes) == 5
    assert layout.get("/secrets").is_dir is True
    assert layout.get("/secrets/id_rsa").is_dir is False


def test_children_listing():
    layout = _load(VALID)
    assert sorted(layout.children_of("/")) == ["pub", "secrets"]
    assert sorted(layout.children_of("/secrets")) == ["id_rsa", "note.txt"]
    # A file has no children listing.
    assert layout.children_of("/secrets/id_rsa") is None


def test_size_and_mode_parsing():
    layout = _load(VALID)
    key = layout.get("/secrets/id_rsa")
    assert key.size == 2048
    assert key.mode == 0o600
    # Blank mode on a file defaults to 0644, blank size stays 0.
    note = layout.get("/secrets/note.txt")
    assert note.mode == layout_module.DEFAULT_FILE_MODE
    assert note.size == 0
    # Explicit directory mode is honored.
    assert layout.get("/secrets").mode == 0o700
    # Blank mode on a directory defaults to 0755.
    assert layout.get("/pub").mode == layout_module.DEFAULT_DIR_MODE


def test_full_mode_sets_type_bits():
    layout = _load(VALID)
    dir_mode = layout_module.full_mode(layout.get("/secrets"))
    file_mode = layout_module.full_mode(layout.get("/secrets/id_rsa"))
    assert dir_mode & stat_module.S_IFDIR
    assert file_mode & stat_module.S_IFREG


def test_comments_and_blank_lines_ignored():
    text = (
        "# a comment\n"
        "\n"
        "path,is_dir,size,mtime,mode,decoy_class,content_ref\n"
        "# another comment\n"
        "/a,1,,0,,,\n"
    )
    layout = _load(text)
    assert layout.get("/a") is not None


def test_missing_parent_is_rejected():
    text = (
        "path,is_dir,size,mtime,mode,decoy_class,content_ref\n"
        "/a/b,0,10,0,,,\n"
    )
    with pytest.raises(layout_module.LayoutError):
        _load(text)


def test_duplicate_path_is_rejected():
    text = (
        "path,is_dir,size,mtime,mode,decoy_class,content_ref\n"
        "/a,1,,0,,,\n"
        "/a,1,,0,,,\n"
    )
    with pytest.raises(layout_module.LayoutError):
        _load(text)


def test_bad_header_is_rejected():
    text = "path,is_dir\n/a,1\n"
    with pytest.raises(layout_module.LayoutError):
        _load(text)


def test_relative_path_is_rejected():
    text = (
        "path,is_dir,size,mtime,mode,decoy_class,content_ref\n"
        "a,1,,0,,,\n"
    )
    with pytest.raises(layout_module.LayoutError):
        _load(text)


def test_packaged_sample_parses():
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    sample = os.path.join(here, "..", "examples", "layout.csv")
    layout = layout_module.load(sample)
    assert layout.get("/secrets/id_rsa") is not None
