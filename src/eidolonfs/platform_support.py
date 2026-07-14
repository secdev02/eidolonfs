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
        # WinFsp exposes winfsp-x64.dll / winfsp-x86.dll under its bin
        # directory. That directory is not on PATH by default, so we resolve it
        # the same way the refuse and fusepy bindings do: the FUSE_LIBRARY_PATH
        # override, then the WinFsp install directory recorded in the registry,
        # then the default install locations. WinFsp installs under
        # "Program Files (x86)" even on 64-bit Windows.
        arch = "x64" if sys.maxsize > 0xFFFFFFFF else "x86"
        dll_name = "winfsp-" + arch + ".dll"

        candidates = []
        override = os.environ.get("FUSE_LIBRARY_PATH")
        if override:
            candidates.append(override)

        install_dir = _winfsp_install_dir()
        if install_dir:
            candidates.append(os.path.join(install_dir, "bin", dll_name))

        for pf_env in ("ProgramFiles(x86)", "ProgramW6432", "ProgramFiles"):
            base = os.environ.get(pf_env)
            if base:
                candidates.append(os.path.join(base, "WinFsp", "bin", dll_name))

        # Last resort: bare name, in case the bin directory is already on PATH.
        candidates.append(dll_name)

        for candidate in candidates:
            try:
                ctypes.WinDLL(candidate)
                return True, "loaded " + candidate
            except OSError:
                continue
        return False, "WinFsp (" + dll_name + ") not found"

    return False, "unsupported platform: " + str(system)


def _winfsp_install_dir():
    """Read the WinFsp install directory from the registry, or None.

    WinFsp records its location under HKLM\\SOFTWARE\\WinFsp (stored in the
    32-bit WOW6432Node view on 64-bit Windows). This is the authoritative
    source the FUSE bindings themselves consult.
    """
    try:
        import winreg
    except ImportError:
        return None
    for flag in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WinFsp",
                0, winreg.KEY_READ | flag,
            ) as key:
                value, _ = winreg.QueryValueEx(key, "InstallDir")
                if value:
                    return value
        except OSError:
            continue
    return None


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