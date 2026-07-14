# EidolonFS Architecture

EidolonFS is a deception filesystem. It presents a tree of convincing but
entirely synthetic decoy files (fake credentials, keys, financial and HR
documents) and raises a verbose, attributed alert the moment someone opens,
reads, or copies one of them. Listing and stat-ing that tree stays silent,
because that is background noise; deliberately opening a decoy is the signal.

This is a Python, FUSE-based successor to the earlier Windows-only EidolonFS
(ProjFS in C#, later a Rust port). Moving to FUSE is what buys a single
codebase across Linux, macOS, and Windows.

## One codebase, three operating systems

FUSE (Filesystem in Userspace) lets an ordinary user-space process answer
kernel filesystem calls. Each OS provides its own native driver, but all three
expose a compatible high-level API:

| OS      | Native driver | License                         | How EidolonFS reaches it |
|---------|---------------|---------------------------------|--------------------------|
| Linux   | libfuse       | LGPL-2.1                        | `refuse` via ctypes      |
| macOS   | macFUSE       | BSD-style, open source          | `refuse` via ctypes      |
| Windows | WinFsp        | GPLv3 with linking exception    | `refuse` via WinFsp FUSE layer |

The Python binding is [`refuse`](https://pypi.org/project/refuse/) (ISC
license), a maintained cross-platform fork of `fusepy`. Both are pure ctypes
bindings with an identical `Operations` class, so `vfs.py` imports whichever is
present and the honeypot logic never has to branch on OS. Process attribution
uses [`psutil`](https://pypi.org/project/psutil/) (BSD-3). Everything in the
pip dependency chain is free and open source.

The one thing pip cannot install is the native driver itself, because it lives
in kernel or system space and needs an administrator. `platform_support.py`
detects the OS, probes for the driver, and prints exact per-OS install commands
when it is missing, then refuses to pretend the honeypot is live when it is not.

## Component map

```
                         eidolonfs mount --csv layout.csv --mountpoint ...
                                          |
                                     cli.py (argparse)
                                          |
         +--------------------+-----------+-----------+--------------------+
         |                    |                       |                    |
 platform_support.py     layout.py               content.py           events.py
 (driver preflight)   (CSV -> tree, O(1)      (synthetic bytes,     (JSON-lines alerts,
                       path lookup)            sized to declared     PID attribution,
                                               size, cached)         log policy)
                                          |
                                        vfs.py
                          (EidolonOperations: the FUSE handlers)
                                          |
                                 refuse / fusepy  ->  libfuse / macFUSE / WinFsp
```

## The CSV metadata model

The virtual tree is declared by a CSV file, keeping the same file-metadata
approach as prior EidolonFS builds (one row per path, parents before children),
now with a header so it opens in any spreadsheet.

```
path,is_dir,size,mtime,mode,decoy_class,content_ref
/secrets,1,,1704067200,0700,,
/secrets/id_rsa,0,2048,1704067200,0600,credential,pem
```

`layout.py` parses this into a `Node` per path and indexes every node by path
for constant-time `getattr` and `readdir`. It validates that every parent
exists before its children and reports the first gap. `decoy_class` tags each
file for alert grouping and priority; `content_ref` selects a content template
or points at an opt-in seed file.

`content.py` synthesizes the bytes a reader receives. Content is deterministic
per path (so partial and repeated reads stay consistent) and is padded or
truncated to the size the CSV declared, so what `stat` reports equals what
`read` returns. Nothing real is ever exposed unless the operator sets a
`--seed-root` and references files under it.

## The logging policy: enumeration is silent, access is loud

This is the core design constraint and it is enforced structurally, not by
after-the-fact filtering.

Silent handlers (never call `emit`): `getattr`, `readdir`, `access`,
`statfs`, `opendir`, `releasedir`, `chmod`, `chown`, `utimens`. These fire
constantly from indexers, backup agents, antivirus, and file managers just
walking the tree. Logging them buries the one event that matters.

Loud handlers (always `emit`):

- `open` records an explicit open, with the caller resolved to process name,
  executable, command line, uid, gid, and pid.
- `read` emits once per handle on the first read that returns data, so
  exfiltration is captured even if the process is killed before a clean close.
- `release` renders a copy verdict (see below).
- Every write-side handler (`create`, `write`, `truncate`, `unlink`, `rename`,
  `mkdir`, `rmdir`) logs the attempt, then refuses it in the default read-only
  mode. An attacker trying to plant or alter files is itself a strong signal.

`events.NEVER_LOG` names the silent set explicitly so the boundary is
auditable rather than implied.

## Detecting a copy

FUSE has no "copy" opcode. Copying a decoy out of the honeypot appears as an
`open` for reading followed by a full sequential read. EidolonFS therefore
infers a copy at `release`: if the handle read at least `--copy-ratio` of the
declared size (default 0.9) and cleared a `--copy-bytes` floor (default 4096,
so a small file opened once by an editor does not false-positive), it emits
`COPY_SUSPECTED` with the total bytes read. The plain `open` and first `read`
are already logged regardless, so even an aborted copy leaves a trail.

## Alert output

Alerts are JSON lines, one event per line, so they drop straight into a SIEM,
`jq`, or a file-tail alerting pipeline with no parsing glue. The same event is
optionally mirrored as a compact human-readable line to the console. Each
record carries the UTC timestamp, event type, path, decoy class, uid, gid, and
the full process attribution.

## Safety posture

Default read-only. The filesystem serves only synthetic content. Write attempts
are logged and refused. A `--seed-root` for exposing real files is strictly
opt-in and path-jailed to the given directory. The honeypot never executes
anything it serves and never reads outside its declared tree.
