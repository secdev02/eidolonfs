"""Command line interface. Installed as the `eidolonfs` console script.

Subcommands
-----------
  eidolonfs check                 Verify the native FUSE driver is installed.
  eidolonfs sample [--out FILE]   Write a starter CSV layout you can edit.
  eidolonfs mount ...             Load a CSV layout and mount the honeypot.
"""

import argparse
import os
import sys

from . import __version__
from . import platform_support
from . import layout as layout_module
from . import content as content_module
from . import events as events_module


def _cmd_check(args):
    system = platform_support.current_os()
    print("EidolonFS " + __version__ + " on " + system)
    ok, detail = platform_support.preflight(exit_on_failure=False)
    if ok:
        print("Native FUSE driver: OK (" + detail + ")")
        return 0
    print("Native FUSE driver: MISSING (" + detail + ")")
    return 3


def _cmd_sample(args):
    here = os.path.dirname(os.path.abspath(__file__))
    sample_path = os.path.normpath(os.path.join(here, "..", "..", "examples", "layout.csv"))
    if not os.path.isfile(sample_path):
        # Fall back to generating one inline if the packaged sample is absent.
        text = _INLINE_SAMPLE
    else:
        with open(sample_path, "r", encoding="utf-8") as handle:
            text = handle.read()

    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        print("Wrote sample layout to " + args.out)
    else:
        sys.stdout.write(text)
    return 0


def _cmd_mount(args):
    # Refuse to run without the native driver, unless the operator forces it.
    if not args.skip_preflight:
        platform_support.preflight(exit_on_failure=True)

    try:
        layout = layout_module.load(args.csv)
    except layout_module.LayoutError as error:
        print("Layout error: " + str(error), file=sys.stderr)
        return 2

    content_store = content_module.ContentStore(seed_root=args.seed_root)

    event_logger = events_module.EventLogger(
        log_path=args.log,
        echo_console=not args.no_console,
        min_copy_ratio=args.copy_ratio,
        min_copy_bytes=args.copy_bytes,
    )

    # Import here so `eidolonfs check` and `sample` work even before the native
    # driver is installed (vfs imports the FUSE binding at module load).
    from . import vfs

    read_only = not args.writable
    print("Mounting EidolonFS at " + args.mountpoint
          + " (read_only=" + str(read_only) + ", log=" + str(args.log) + ")")
    try:
        vfs.mount(
            layout=layout,
            content_store=content_store,
            event_logger=event_logger,
            mountpoint=args.mountpoint,
            read_only=read_only,
            foreground=True,
            allow_other=args.allow_other,
        )
    except RuntimeError as error:
        # fusepy and refuse raise RuntimeError when the mount itself fails.
        print("Mount failed: " + str(error), file=sys.stderr)
        return 4
    finally:
        event_logger.close()
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="eidolonfs",
        description="Cross-platform FUSE honeypot that alerts on decoy file open and copy.",
    )
    parser.add_argument("--version", action="version",
                        version="EidolonFS " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="verify the native FUSE driver is installed")
    check.set_defaults(func=_cmd_check)

    sample = sub.add_parser("sample", help="write a starter CSV layout")
    sample.add_argument("--out", help="file to write (default: stdout)")
    sample.set_defaults(func=_cmd_sample)

    mount = sub.add_parser("mount", help="mount the honeypot from a CSV layout")
    mount.add_argument("--csv", required=True, help="path to the CSV metadata file")
    mount.add_argument("--mountpoint", required=True,
                       help="mount target (a directory on Linux/macOS, a drive or path on Windows)")
    mount.add_argument("--log", default="eidolonfs-events.jsonl",
                       help="JSON-lines alert log path (default: eidolonfs-events.jsonl)")
    mount.add_argument("--seed-root", default=None,
                       help="optional read-only directory of real files to expose via content_ref")
    mount.add_argument("--writable", action="store_true",
                       help="allow writes instead of refusing them (still logged)")
    mount.add_argument("--allow-other", action="store_true",
                       help="let other users see the mount (needs FUSE allow_other permission)")
    mount.add_argument("--no-console", action="store_true",
                       help="do not mirror alerts to the console")
    mount.add_argument("--copy-ratio", type=float, default=0.9,
                       help="fraction of a file that must be read to flag a suspected copy")
    mount.add_argument("--copy-bytes", type=int, default=4096,
                       help="minimum bytes read before a suspected copy can fire")
    mount.add_argument("--skip-preflight", action="store_true",
                       help="skip the native driver check (advanced)")
    mount.set_defaults(func=_cmd_mount)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


_INLINE_SAMPLE = """\
# EidolonFS layout. Parents before children. Lines starting with # are comments.
path,is_dir,size,mtime,mode,decoy_class,content_ref
/finance,1,,1704067200,0755,,
/finance/payroll_2024.csv,0,4096,1704067200,0640,financial,csv
/secrets,1,,1704067200,0700,,
/secrets/id_rsa,0,2048,1704067200,0600,credential,pem
/secrets/aws.env,0,512,1704067200,0600,credential,env
"""


if __name__ == "__main__":
    raise SystemExit(main())
