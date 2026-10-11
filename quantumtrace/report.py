"""Self-contained report using the same UI for the app and offline export."""

import json
from pathlib import Path

WEB = Path(__file__).with_name("web")


def render_html(report, embedded=False):
    # Historic reports retain their findings/policy; only this view is derived.
    if "priorities" not in report:
        from .inventory import build_priorities
        report = {**report, "priorities": build_priorities(report["findings"])}
    # User-controlled strings cannot close the data tag. The UI only inserts
    # evidence with textContent; the report makes no resource requests.
    payload = json.dumps(report, ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    template = (WEB / "report.html").read_text(encoding="utf-8")
    return (template.replace("__REPORT_CSS__", (WEB / "report.css").read_text(encoding="utf-8"))
            .replace("__REPORT_JS__", (WEB / "report.js").read_text(encoding="utf-8"))
            .replace("__REPORT_MODE__", "embedded" if embedded else "standalone")
            .replace("__REPORT_DATA__", payload))


def write_reports(report, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    (directory / "report.html").write_text(render_html(report), encoding="utf-8")
    return directory / "report.html", directory / "report.json"
