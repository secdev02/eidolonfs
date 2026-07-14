"""Event logging and the log policy.

The whole point of this module is one distinction the operator asked for:

  ENUMERATION is silent.   Listing a directory or stat-ing a file is what any
                           normal indexer, backup agent, or file manager does
                           constantly. Logging it drowns the signal.

  ACCESS is loud.          An explicit open, the reads that follow, and the
                           copy those reads add up to are deliberate acts
                           against a file that has no legitimate reason to be
                           touched. Every one gets a verbose, attributed alert.

The FUSE layer enforces this by only calling emit() for the loud operations.
The NEVER_LOG set below documents the silent ones so the boundary is explicit
and auditable rather than implied by which handlers happen to call emit().
"""

import datetime
import io
import json
import os
import threading

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


# Loud events. These are the only things EidolonFS writes to the alert log.
OPEN = "OPEN"
READ = "READ"
COPY_SUSPECTED = "COPY_SUSPECTED"
WRITE = "WRITE"
CREATE = "CREATE"
TRUNCATE = "TRUNCATE"
UNLINK = "UNLINK"
RENAME = "RENAME"
MKDIR = "MKDIR"
RMDIR = "RMDIR"
MOUNT = "MOUNT"
UNMOUNT = "UNMOUNT"

# Silent operations. Listed for documentation and self-audit. The vfs must
# never call emit() for any of these. If you find yourself wanting to, add a
# separate debug channel instead of polluting the alert stream.
NEVER_LOG = frozenset({
    "getattr", "readdir", "opendir", "releasedir", "access",
    "statfs", "readlink", "listxattr", "getxattr", "fgetattr", "flush",
})


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def is_suspected_copy(bytes_read, declared_size, min_ratio, min_bytes):
    """Decide whether a completed read looks like a copy of the whole file.

    FUSE has no copy opcode, so a copy out of the honeypot appears as a full
    sequential read. We call it a copy when the reader pulled at least
    min_ratio of the declared size and also cleared the min_bytes floor, so a
    single editor peek at a tiny file does not false-positive.
    """
    if declared_size <= 0:
        return False
    if bytes_read < min_bytes:
        return False
    return bytes_read >= min_ratio * declared_size


def attribute(pid):
    """Resolve a PID to process name, executable, and command line.

    FUSE gives us the caller's uid, gid, and pid through fuse_get_context.
    psutil turns the pid into something a responder can act on. Attribution is
    best-effort: short-lived processes may already be gone by the time we look.
    """
    info = {"pid": pid, "process": None, "exe": None, "cmdline": None, "username": None}
    if psutil is None or pid in (None, 0):
        return info
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            info["process"] = proc.name()
            try:
                info["exe"] = proc.exe()
            except Exception:
                pass
            try:
                info["cmdline"] = " ".join(proc.cmdline())
            except Exception:
                pass
            try:
                info["username"] = proc.username()
            except Exception:
                pass
    except Exception:
        # Process vanished or access denied. Leave the fields as None.
        pass
    return info


class EventLogger:
    """Append-only JSON-lines alert sink with optional console mirroring.

    JSON lines were chosen so the output drops straight into a SIEM, jq, or a
    file-tail alerting pipeline without parsing glue. One event per line.
    """

    def __init__(self, log_path, echo_console=True, min_copy_ratio=0.9,
                 min_copy_bytes=4096):
        self.log_path = log_path
        self.echo_console = echo_console
        # Copy heuristic thresholds, explained in vfs.release.
        self.min_copy_ratio = min_copy_ratio
        self.min_copy_bytes = min_copy_bytes
        self._lock = threading.Lock()
        self._handle = None
        if log_path:
            directory = os.path.dirname(os.path.abspath(log_path))
            if directory and not os.path.isdir(directory):
                os.makedirs(directory, exist_ok=True)
            self._handle = io.open(log_path, "a", encoding="utf-8")

    def emit(self, event_type, path, context=None, decoy_class="", **extra):
        """Write one loud event. context is (uid, gid, pid) from FUSE."""
        uid = gid = pid = None
        if context is not None:
            uid, gid, pid = context

        record = {
            "ts": _utc_now(),
            "event": event_type,
            "path": path,
            "decoy_class": decoy_class,
            "uid": uid,
            "gid": gid,
        }
        record.update(attribute(pid))
        if extra:
            record.update(extra)

        line = json.dumps(record, ensure_ascii=False)
        with self._lock:
            if self._handle is not None:
                self._handle.write(line + "\n")
                self._handle.flush()
            if self.echo_console:
                # A compact one-liner for a human watching a terminal.
                summary = "[" + record["ts"] + "] " + event_type + " " + str(path)
                proc = record.get("process")
                if proc:
                    summary += " by " + str(proc) + " (pid " + str(pid) + ")"
                if decoy_class:
                    summary += " class=" + decoy_class
                for key in ("bytes_read", "size", "detail"):
                    if key in extra:
                        summary += " " + key + "=" + str(extra[key])
                print(summary)

        return record

    def close(self):
        with self._lock:
            if self._handle is not None:
                self._handle.close()
                self._handle = None
