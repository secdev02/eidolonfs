"""The FUSE operations class.

This is where the honeypot behavior lives. Read carefully which handlers call
self.events.emit and which do not, because that split is the feature:

  Silent  : getattr, readdir, access, statfs, opendir, releasedir, ...
  Loud    : open, read (first), release (copy verdict), and every write-side
            operation (create, write, truncate, unlink, rename, mkdir, rmdir).

The tree, its metadata, and its content are all synthetic, driven by the CSV
layout and the content store. Nothing here reads a real file unless the
operator deliberately configured a seed root.
"""

from errno import EACCES, ENOENT, EROFS
import threading

# Prefer refuse (maintained cross-platform fork). Fall back to fusepy. Both
# expose the same high-level API: FUSE, Operations, FuseOSError, and the
# fuse_get_context helper that yields the caller's (uid, gid, pid).
try:
    from refuse.high import FUSE, FuseOSError, Operations, fuse_get_context
    _BINDING = "refuse"
except ImportError:  # pragma: no cover
    from fuse import FUSE, FuseOSError, Operations, fuse_get_context
    _BINDING = "fusepy"

from . import events
from . import layout as layout_module


class EidolonOperations(Operations):
    """A read-only-by-default deceptive filesystem."""

    def __init__(self, layout, content_store, event_logger, read_only=True):
        self.layout = layout
        self.content = content_store
        self.events = event_logger
        self.read_only = read_only

        # Open-handle table. Each entry tracks enough to render a copy verdict
        # at release time without logging on every single read call.
        self._handles = {}
        self._next_fh = 1
        self._lock = threading.Lock()

    # ---- helpers -----------------------------------------------------------

    def _require(self, path):
        node = self.layout.get(path)
        if node is None:
            raise FuseOSError(ENOENT)
        return node

    def _new_handle(self, node, flags):
        with self._lock:
            fh = self._next_fh
            self._next_fh += 1
            self._handles[fh] = {
                "path": node.path,
                "flags": flags,
                "size": node.size,
                "decoy_class": node.decoy_class,
                "bytes_read": 0,
                "read_logged": False,
            }
        return fh

    # ---- SILENT: enumeration and metadata ----------------------------------
    # None of the handlers below emit an alert. This is deliberate. Listing and
    # stat-ing are ambient background noise from indexers and file managers.

    def getattr(self, path, fh=None):
        node = self._require(path)
        return {
            "st_mode": layout_module.full_mode(node),
            "st_nlink": 2 if node.is_dir else 1,
            "st_size": 0 if node.is_dir else node.size,
            "st_ctime": node.mtime,
            "st_mtime": node.mtime,
            "st_atime": node.mtime,
            "st_uid": 0,
            "st_gid": 0,
        }

    def readdir(self, path, fh):
        node = self._require(path)
        if not node.is_dir:
            raise FuseOSError(ENOENT)
        entries = [".", ".."]
        children = self.layout.children_of(path) or []
        entries.extend(children)
        return entries

    def access(self, path, amode):
        # Confirm existence, then permit. Denying here just tips off the caller.
        self._require(path)
        return 0

    def opendir(self, path):
        self._require(path)
        return 0

    def releasedir(self, path, fh):
        return 0

    def statfs(self, path):
        # Plausible but generic filesystem stats.
        return {
            "f_bsize": 4096,
            "f_frsize": 4096,
            "f_blocks": 1048576,
            "f_bfree": 524288,
            "f_bavail": 524288,
            "f_files": 65536,
            "f_ffree": 32768,
            "f_namemax": 255,
        }

    def chmod(self, path, mode):
        # Silently accepted no-op. Metadata fiddling is not the signal we want.
        self._require(path)
        return 0

    def chown(self, path, uid, gid):
        self._require(path)
        return 0

    def utimens(self, path, times=None):
        self._require(path)
        return 0

    # ---- LOUD: explicit access ---------------------------------------------

    def open(self, path, flags):
        node = self._require(path)
        if node.is_dir:
            raise FuseOSError(EACCES)

        context = fuse_get_context()
        # If this open carries write intent and we are read-only, log it as a
        # write attempt (tamper) rather than a plain open, then refuse.
        write_intent = bool(flags & (0o1 | 0o2))  # O_WRONLY | O_RDWR
        if write_intent and self.read_only:
            self.events.emit(
                events.WRITE, path, context=context,
                decoy_class=node.decoy_class, detail="open-for-write refused",
            )
            raise FuseOSError(EROFS)

        self.events.emit(
            events.OPEN, path, context=context,
            decoy_class=node.decoy_class, size=node.size,
        )
        return self._new_handle(node, flags)

    def read(self, path, size, offset, fh):
        handle = self._handles.get(fh)
        node = self._require(path)
        data = self.content.render(node)
        chunk = data[offset:offset + size]

        if handle is not None:
            handle["bytes_read"] += len(chunk)
            # Log the first read that actually returns bytes. This captures
            # exfiltration even if the process is killed before a clean
            # release, without logging on every read call.
            if not handle["read_logged"] and chunk:
                handle["read_logged"] = True
                self.events.emit(
                    events.READ, path, context=fuse_get_context(),
                    decoy_class=handle["decoy_class"],
                    offset=offset, size=node.size,
                )
        return chunk

    def release(self, path, fh):
        handle = self._handles.pop(fh, None)
        if handle is None:
            return 0

        total = handle["bytes_read"]
        declared = handle["size"]
        # Copy verdict is a pure function in events, shared with the tests.
        if events.is_suspected_copy(
            total, declared,
            self.events.min_copy_ratio, self.events.min_copy_bytes,
        ):
            self.events.emit(
                events.COPY_SUSPECTED, path, context=fuse_get_context(),
                decoy_class=handle["decoy_class"],
                bytes_read=total, size=declared,
            )
        return 0

    # ---- LOUD: write-side tamper attempts ----------------------------------
    # Read-only mode refuses these but always logs the attempt first, because
    # an attacker trying to plant or alter files is a strong signal.

    def create(self, path, mode, fi=None):
        if self.read_only:
            self.events.emit(
                events.CREATE, path, context=fuse_get_context(),
                detail="create refused",
            )
            raise FuseOSError(EROFS)
        raise FuseOSError(EROFS)

    def write(self, path, data, offset, fh):
        self.events.emit(
            events.WRITE, path, context=fuse_get_context(),
            offset=offset, size=len(data), detail="write refused",
        )
        raise FuseOSError(EROFS)

    def truncate(self, path, length, fh=None):
        self.events.emit(
            events.TRUNCATE, path, context=fuse_get_context(),
            detail="truncate refused",
        )
        raise FuseOSError(EROFS)

    def unlink(self, path):
        self.events.emit(
            events.UNLINK, path, context=fuse_get_context(),
            detail="unlink refused",
        )
        raise FuseOSError(EROFS)

    def rename(self, old, new):
        self.events.emit(
            events.RENAME, old, context=fuse_get_context(),
            detail="rename refused", new_path=new,
        )
        raise FuseOSError(EROFS)

    def mkdir(self, path, mode):
        self.events.emit(
            events.MKDIR, path, context=fuse_get_context(),
            detail="mkdir refused",
        )
        raise FuseOSError(EROFS)

    def rmdir(self, path):
        self.events.emit(
            events.RMDIR, path, context=fuse_get_context(),
            detail="rmdir refused",
        )
        raise FuseOSError(EROFS)


def mount(layout, content_store, event_logger, mountpoint, read_only=True,
          foreground=True, allow_other=False):
    """Build the operations object and hand control to the FUSE main loop.

    This call blocks until the filesystem is unmounted.
    """
    operations = EidolonOperations(
        layout=layout,
        content_store=content_store,
        event_logger=event_logger,
        read_only=read_only,
    )
    event_logger.emit(events.MOUNT, mountpoint, context=None,
                      detail="binding=" + _BINDING)
    try:
        FUSE(
            operations,
            mountpoint,
            foreground=foreground,
            allow_other=allow_other,
            ro=read_only,
            nothreads=False,
        )
    finally:
        event_logger.emit(events.UNMOUNT, mountpoint, context=None)
