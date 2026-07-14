"""Tests for event logging, the log policy, and the copy heuristic."""

import json

from eidolonfs import events as events_module


def test_emit_writes_json_lines(tmp_path):
    log_path = str(tmp_path / "events.jsonl")
    logger = events_module.EventLogger(log_path=log_path, echo_console=False)
    logger.emit(
        events_module.OPEN, "/secrets/id_rsa",
        context=(1000, 1000, None), decoy_class="credential", size=2048,
    )
    logger.close()

    lines = [line for line in open(log_path).read().splitlines() if line]
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["event"] == "OPEN"
    assert record["path"] == "/secrets/id_rsa"
    assert record["decoy_class"] == "credential"
    assert record["uid"] == 1000
    assert record["size"] == 2048
    assert "ts" in record and "pid" in record


def test_emit_appends(tmp_path):
    log_path = str(tmp_path / "events.jsonl")
    logger = events_module.EventLogger(log_path=log_path, echo_console=False)
    logger.emit(events_module.OPEN, "/a", context=(0, 0, None))
    logger.emit(events_module.COPY_SUSPECTED, "/a", context=(0, 0, None))
    logger.close()
    lines = [line for line in open(log_path).read().splitlines() if line]
    assert len(lines) == 2


def test_enumeration_ops_are_documented_as_silent():
    # The silent set is the contract. These must never be emitted.
    for op in ("getattr", "readdir", "access", "statfs", "opendir"):
        assert op in events_module.NEVER_LOG


def test_attribute_handles_missing_pid():
    info = events_module.attribute(None)
    assert info["pid"] is None
    assert info["process"] is None


def test_copy_heuristic_full_read_is_a_copy():
    assert events_module.is_suspected_copy(8192, 8192, 0.9, 4096) is True


def test_copy_heuristic_partial_read_below_ratio():
    # Half of the file read, ratio requires 90 percent.
    assert events_module.is_suspected_copy(4096, 8192, 0.9, 4096) is False


def test_copy_heuristic_small_file_below_floor():
    # Whole file read, but it is tiny and below the byte floor.
    assert events_module.is_suspected_copy(100, 100, 0.9, 4096) is False


def test_copy_heuristic_zero_size_never_copies():
    assert events_module.is_suspected_copy(0, 0, 0.9, 4096) is False


def test_copy_heuristic_boundary_ratio_exact():
    # Exactly at the ratio and above the floor counts.
    assert events_module.is_suspected_copy(9000, 10000, 0.9, 4096) is True
