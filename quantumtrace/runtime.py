"""Optional tools, including the standard Windows Wireshark location."""

import importlib.util
import os
import shutil
import sys
from pathlib import Path


def find_tshark():
    executable = shutil.which("tshark")
    if executable:
        return executable
    if os.name == "nt":
        for variable in ("ProgramFiles", "ProgramFiles(x86)"):
            root = os.environ.get(variable)
            if root:
                candidate = Path(root) / "Wireshark" / "tshark.exe"
                if candidate.is_file():
                    return str(candidate)
    return None


def diagnostics():
    return {"python": sys.version.split()[0], "tshark": bool(find_tshark()),
            "cryptography": bool(importlib.util.find_spec("cryptography")),
            "core_requires_paid_api": False}
