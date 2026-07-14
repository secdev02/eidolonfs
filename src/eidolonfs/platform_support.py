"""Platform detection and native FUSE driver preflight.

pip installs the Python bindings (refuse or fusepy) but it cannot install the
native FUSE driver, which lives in kernel or system space and needs an
administrator. This module detects the current OS, tries to locate the native
driver, and prints exact install guidance when it is missing. It never fails
silently: a honeypot that is not actually mounted is worse than no honeypot.
"""

import ctypes
import ctypes.util
import os
import platform
import sys


LINUX = "linux"
MACOS = "darwin"
WINDOWS = "windows"


def current_os():
    """Return one of LINUX, MACOS, WINDOWS, or the raw platform string."""
    name = platform.system().lower()
    if name.startswith("linux"):
        return LINUX
    if name == "darwin":
        return MACOS
    if name.startswith("win"):
        return WINDOWS
    return name


# Human readable, copy-paste install guidance per operating system.
INSTALL_HINTS = {
    LINUX: (
        "libfuse is required.\n"
        "  Debian / Ubuntu : sudo apt-get install fuse3 libfuse2\n"
        "  Fedora / RHEL   : sudo dnf install fuse fuse-libs\n"
        "  Arch            : sudo pacman -S fuse2 fuse3\n"
        "Also ensure your user may mount FUSE volumes (the 'fuse' group or\n"
        "'user_allow_other' in /etc/fuse.conf if you pass --allow-other)."
    ),
    MACOS: (
        "macFUSE is required (free, open source).\n"
        "  Homebrew : brew install --cask macfuse\n"
        "  Manual   : https://osxfuse.github.io/\n"
        "After install, approve the system extension under\n"
        "System Settings > Privacy and Security, then reboot once."
    ),
    WINDOWS: (
        "WinFsp is required (free, open source, GPLv3 with linking exception).\n"
        "  winget  : winget install WinFsp.WinFsp\n"
        "  choco   : choco install winfsp\n"
        "  Manual  : https://winfsp.dev/rel/\n"
        "Install the core package. The FUSE compatibility layer ships with it."
    ),
}


def _native_library_present():
    """Best-effort check that the native FUSE library can be loaded.

    Returns a tuple of (present, detail). detail is a short string naming what
    was found or what was looked for, useful for the startup log.
    """
    system = current_os()

    if system in (LINUX, MACOS):
        # ctypes.util.find_library resolves libfuse / libfuse3 on Linux and
        # the macFUSE dylib on macOS.
        for name in ("fuse3", "fuse", "osxfuse"):
            found = ctypes.util.find_library(name)
            if found:
                return True, "found " + str(found)
        return False, "libfuse not found on the loader search path"

    if system == WINDOWS:
        # WinFsp exposes winfsp-x64.dll / winfsp-x86.dll. The refuse and
        # fusepy bindings look for it under the WinFsp install directory,
        # discoverable through the WinFsp registry key or PATH.
        dll = "winfsp-x64.dll" if sys.maxsize > 2 ** 32 else "winfsp-x86.dll"
        try:
            ctypes.WinDLL(dll)
            return True, "loaded " + dll
        except OSError:
            # Fall back to the documented install path.
            candidate = os.path.join(
                os.environ.get("ProgramFiles", "C:\\Program Files"),
                "WinFsp", "bin", dll,
            )
            if os.path.exists(candidate):
                return True, "found " + candidate
            return False, "WinFsp (" + dll + ") not found"

    return False, "unsupported platform: " + str(system)


def preflight(exit_on_failure=True):
    """Verify the native FUSE driver is available before mounting.

    Prints actionable per-OS guidance and, by default, exits with a nonzero
    status when the driver is missing so the operator is never left thinking
    the honeypot is live when it is not.
    """
    system = current_os()
    present, detail = _native_library_present()

    if present:
        return True, detail

    hint = INSTALL_HINTS.get(system, "No install guidance for this platform.")
    message = (
        "EidolonFS cannot start: the native FUSE driver is not installed.\n"
        + "Detail: " + detail + "\n\n"
        + hint + "\n\n"
        + "pip installed the Python side only. The driver installs separately\n"
        + "because it needs administrator or kernel-level access."
    )
    print(message, file=sys.stderr)

    if exit_on_failure:
        raise SystemExit(3)
    return False, detail
