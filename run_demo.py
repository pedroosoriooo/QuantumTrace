"""Run the supplied starter dataset from any working directory."""

from pathlib import Path

from quantumtrace.cli import main

if __name__ == "__main__":
    root = Path(__file__).resolve().parent
    raise SystemExit(main(["scan", str(root / "data"), "--out", str(root / "reports")]))
