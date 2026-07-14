# EidolonFS

A cross-platform FUSE honeypot filesystem. It projects a tree of convincing but
entirely synthetic decoy files (fake credentials, keys, financial and HR
documents) described by a CSV, and raises a verbose, attributed alert the moment
someone opens, reads, or copies one. Directory listing and stat calls stay
silent, because deliberately opening a decoy is the signal worth catching.

```
An eidolon is a phantom double, an insubstantial image of something real, which is exactly what EidolonFS serves: files that look like genuine secrets but are entirely illusory, and that quietly raise the alarm the moment anyone touches them.
```


Runs on Linux, macOS, and Windows from one codebase. Every dependency is free
and open source.

## Install

EidolonFS is not published to a package index. Install it from source, from a
built wheel, or straight from the repository. Any of these install the
`eidolonfs` command and the importable `eidolonfs` package.

From the repository:

```
pip install git+https://github.com/YOUR_USERNAME/EidolonFS.git
```

From a local checkout (run inside the extracted project folder):

```
pip install .
```

From a built wheel, if you were handed one:

```
pip install eidolonfs-2.0.0-py3-none-any.whl
```

That installs the Python side. FUSE also needs a native driver, which pip
cannot install because it lives in system or kernel space. Install it once per
machine:

- Linux: `sudo apt-get install libfuse2t64 fuse` (the package is `libfuse2` on
  releases older than Ubuntu 24.04; use `fuse-libs` on Fedora/RHEL)
- macOS: `brew install --cask macfuse`, then approve the system extension and
  reboot once
- Windows: `winget install WinFsp.WinFsp`

Check that the driver is present:

```
eidolonfs check
```

Installing still pulls the two runtime dependencies (`refuse` and `psutil`)
from PyPI. For a fully offline machine, see Building and sharing below.

## Use

Write a starter layout, edit it, then mount:

```
eidolonfs sample --out layout.csv
eidolonfs mount --csv layout.csv --mountpoint /mnt/decoy --log events.jsonl
```

On Windows the mount point is a drive or path, for example
`--mountpoint Z:` or `--mountpoint C:\decoy`.

Now anything that opens or copies a decoy file appears in `events.jsonl` (and
on the console) with the responsible process attributed:

```json
{"ts":"2026-07-14T16:30:28Z","event":"COPY_SUSPECTED","path":"/secrets/id_rsa","decoy_class":"credential","uid":1000,"gid":1000,"pid":4821,"process":"scp","cmdline":"scp /mnt/decoy/secrets/id_rsa attacker@host:","bytes_read":2048,"size":2048}
```

## The layout CSV

One row per path, parents before children, `#` for comments:

```
path,is_dir,size,mtime,mode,decoy_class,content_ref
/secrets,1,,1704067200,0700,,
/secrets/id_rsa,0,2048,1704067200,0600,credential,pem
/secrets/aws.env,0,512,1704067200,0600,credential,env
```

`content_ref` picks a content template (`pem`, `env`, `csv`, `json`, `txt`, or
blank to synthesize by extension). `decoy_class` tags the alert. Content is
sized to match the declared `size`, so what an attacker sees on stat equals what
they can read.

## What gets logged

Loud (alerted): `open`, first `read`, suspected copy at close, and every
refused write, create, rename, or delete.

Silent (never alerted): directory listing, stat, access checks, statfs, and
metadata no-ops. This is deliberate so the alert stream stays clean.

## Options

```
eidolonfs mount
  --csv FILE            layout metadata (required)
  --mountpoint PATH     where to mount (required)
  --log FILE            JSON-lines alert log (default eidolonfs-events.jsonl)
  --seed-root DIR       expose real files via content_ref (opt-in, path-jailed)
  --writable            accept writes instead of refusing them (still logged)
  --allow-other         let other users see the mount
  --no-console          do not mirror alerts to the console
  --copy-ratio F        fraction of a file read to flag a copy (default 0.9)
  --copy-bytes N        minimum bytes read before a copy can fire (default 4096)
```

## Running the tests

```
pip install -e ".[test]"
pytest -m "not mount"     # cross-platform unit tests, no driver needed
pytest -m "mount"         # end-to-end mount test, Linux with libfuse only
pytest                    # everything
```

The unit tests cover the CSV parser, content synthesis, event schema, and the
copy heuristic. The mount test performs a real FUSE mount and asserts the core
contract: listing and stat are silent, while open and full read raise OPEN and
COPY_SUSPECTED. On macOS and Windows the mount test skips, because loading the
kernel extension there needs manual approval and a reboot.

## Building and sharing

EidolonFS is distributed without a package index. Build a wheel and source
archive to hand around or attach to a GitHub release:

```
pip install build
python -m build            # writes dist/*.whl and dist/*.tar.gz
```

Anyone can then install the wheel directly, no index involved:

```
pip install eidolonfs-2.0.0-py3-none-any.whl
```

Or install straight from the repository:

```
pip install git+https://github.com/YOUR_USERNAME/EidolonFS.git
```

Fully offline install: a plain install still fetches `refuse` and `psutil`
from PyPI. To avoid all network access, download those two wheels once on a
connected machine, place them next to the EidolonFS wheel, and install with
`pip install --no-index --find-links . eidolonfs-2.0.0-py3-none-any.whl`.

## License

MIT for EidolonFS itself. Native drivers are licensed separately: libfuse
(LGPL-2.1), macFUSE (BSD-style), WinFsp (GPLv3 with linking exception).

See `ARCHITECTURE.md` for the design in depth.
