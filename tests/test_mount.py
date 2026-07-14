"""End-to-end smoke test that performs a real FUSE mount.

This is the test that actually proves the honeypot's core promise: listing and
stat-ing the tree stays silent, while an explicit open and full read raise
OPEN and COPY_SUSPECTED alerts.

It only runs on Linux with a loadable FUSE binding and driver. Everywhere else
(macOS and Windows runners, where loading the kernel extension needs manual
approval and a reboot) it skips cleanly. Marked "mount" so it can be selected
or excluded with -m.
"""

import json
import os
import subprocess
import sys
import threading
import time

import pytest


pytestmark = pytest.mark.mount


LAYOUT = """\
path,is_dir,size,mtime,mode,decoy_class,content_ref
/vault,1,,1704067200,0755,,
/vault/id_rsa,0,8192,1704067200,0600,credential,txt
"""


def _read_events(log_path):
    if not os.path.exists(log_path):
        return []
    records = []
    with open(log_path) as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _events_of(records, *types):
    wanted = set(types)
    return [record for record in records if record.get("event") in wanted]


def _unmount(mountpoint):
    for tool in (["fusermount", "-u"], ["fusermount3", "-u"], ["umount"]):
        try:
            subprocess.run(tool + [mountpoint], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            continue


def _wait_until_mounted(mountpoint, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.ismount(mountpoint):
            return True
        time.sleep(0.1)
    return False


@pytest.mark.skipif(sys.platform != "linux", reason="live mount test runs on Linux only")
def test_enumeration_silent_open_and_copy_loud(tmp_path):
    # Import the binding lazily so this file can be collected everywhere; skip
    # if the native FUSE library cannot be loaded on this runner.
    try:
        from eidolonfs import vfs
    except (ImportError, OSError) as error:
        pytest.skip("FUSE binding/driver not loadable: " + str(error))

    from eidolonfs import layout as layout_module
    from eidolonfs import content as content_module
    from eidolonfs import events as events_module

    csv_path = tmp_path / "layout.csv"
    csv_path.write_text(LAYOUT)
    log_path = str(tmp_path / "events.jsonl")
    mountpoint = str(tmp_path / "mnt")
    os.makedirs(mountpoint)

    layout = layout_module.load(str(csv_path))
    store = content_module.ContentStore()
    logger = events_module.EventLogger(
        log_path=log_path, echo_console=False,
        min_copy_ratio=0.9, min_copy_bytes=4096,
    )

    mount_error = {}

    def run_mount():
        try:
            vfs.mount(
                layout=layout, content_store=store, event_logger=logger,
                mountpoint=mountpoint, read_only=True, foreground=True,
                allow_other=False,
            )
        except Exception as exc:  # noqa: BLE001
            mount_error["error"] = exc

    thread = threading.Thread(target=run_mount, daemon=True)
    thread.start()

    try:
        if not _wait_until_mounted(mountpoint):
            if "error" in mount_error:
                pytest.skip("mount did not come up: " + str(mount_error["error"]))
            pytest.skip("mount did not come up within timeout")

        target = os.path.join(mountpoint, "vault", "id_rsa")

        # Phase A: enumeration. Listing and stat must produce no loud events.
        assert sorted(os.listdir(mountpoint)) == ["vault"]
        assert os.listdir(os.path.join(mountpoint, "vault")) == ["id_rsa"]
        os.stat(target)
        time.sleep(0.3)

        loud = _events_of(
            _read_events(log_path),
            events_module.OPEN, events_module.READ, events_module.COPY_SUSPECTED,
        )
        assert loud == [], "enumeration should not emit open/read/copy events"

        # Phase B: explicit open and full read. This is a copy out of the vault.
        with open(target, "rb") as handle:
            data = handle.read()
        assert len(data) == 8192

        # Give release a moment to fire the copy verdict.
        deadline = time.time() + 5.0
        opens = copies = []
        while time.time() < deadline:
            records = _read_events(log_path)
            opens = _events_of(records, events_module.OPEN)
            copies = _events_of(records, events_module.COPY_SUSPECTED)
            if opens and copies:
                break
            time.sleep(0.2)

        assert opens, "an explicit open should emit an OPEN alert"
        assert copies, "reading the whole file should emit COPY_SUSPECTED"
        assert opens[0]["path"].endswith("/vault/id_rsa")
        assert copies[0]["bytes_read"] == 8192
        assert copies[0]["decoy_class"] == "credential"
    finally:
        _unmount(mountpoint)
        thread.join(timeout=5.0)
        logger.close()
