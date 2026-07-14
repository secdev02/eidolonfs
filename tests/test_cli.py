"""Tests for the command line interface (non-mounting paths)."""

from eidolonfs import cli
from eidolonfs import layout as layout_module


def test_sample_writes_valid_layout(tmp_path, capsys):
    out = str(tmp_path / "layout.csv")
    rc = cli.main(["sample", "--out", out])
    assert rc == 0
    # The emitted sample must itself be a parseable layout.
    layout = layout_module.load(out)
    assert len(layout.nodes) > 1


def test_sample_to_stdout(capsys):
    rc = cli.main(["sample"])
    assert rc == 0
    printed = capsys.readouterr().out
    assert "path,is_dir,size" in printed


def test_check_returns_0_or_3(capsys):
    # 0 when a native driver is present, 3 when it is not. Either is a valid
    # outcome depending on the runner, but it must never raise.
    rc = cli.main(["check"])
    assert rc in (0, 3)


def test_parser_requires_subcommand():
    import pytest
    with pytest.raises(SystemExit):
        cli.main([])


def test_mount_requires_csv_and_mountpoint():
    import pytest
    with pytest.raises(SystemExit):
        cli.main(["mount"])
