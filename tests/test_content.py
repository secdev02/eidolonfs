"""Tests for synthetic decoy content generation."""

from eidolonfs import content as content_module
from eidolonfs.layout import Node


def _file(path, size=0, content_ref=""):
    return Node(path, False, size, 0, 0o644, "", content_ref)


def test_content_is_sized_to_declared_size():
    store = content_module.ContentStore()
    for size in (1, 100, 512, 8192):
        node = _file("/f_" + str(size), size=size, content_ref="txt")
        data = store.render(node)
        assert len(data) == size


def test_zero_size_uses_natural_template_length():
    store = content_module.ContentStore()
    node = _file("/note.txt", size=0, content_ref="txt")
    data = store.render(node)
    assert len(data) > 0


def test_content_is_deterministic():
    store_a = content_module.ContentStore()
    store_b = content_module.ContentStore()
    node = _file("/secrets/id_rsa", size=2048, content_ref="pem")
    assert store_a.render(node) == store_b.render(node)


def test_template_selected_by_ref():
    store = content_module.ContentStore()
    pem = store.render(_file("/k", size=0, content_ref="pem"))
    assert b"BEGIN PRIVATE KEY" in pem
    env = store.render(_file("/e", size=0, content_ref="env"))
    assert b"AWS_ACCESS_KEY_ID" in env


def test_template_selected_by_extension_when_ref_blank():
    store = content_module.ContentStore()
    csv_data = store.render(_file("/data.csv", size=0, content_ref=""))
    assert b"access_level" in csv_data
    json_data = store.render(_file("/conf.json", size=0, content_ref=""))
    assert b"\"generator\"" in json_data


def test_decoy_marker_present():
    store = content_module.ContentStore()
    data = store.render(_file("/x.txt", size=0, content_ref="txt"))
    assert b"EidolonFS" in data


def test_seed_root_is_path_jailed(tmp_path):
    # A content_ref that tries to escape the seed root must not read outside it.
    secret = tmp_path / "outside.txt"
    secret.write_text("real secret")
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "inside.txt").write_text("seed content")

    store = content_module.ContentStore(seed_root=str(seed))
    # Legitimate reference inside the seed root works.
    inside = store.render(_file("/a", size=0, content_ref="inside.txt"))
    assert inside == b"seed content"
    # Traversal reference falls back to a synthesized template, never the file.
    escaped = store.render(_file("/b.txt", size=0, content_ref="../outside.txt"))
    assert b"real secret" not in escaped
