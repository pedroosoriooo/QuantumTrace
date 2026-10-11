"""Compare a passive scan with manual expectations; never execute input files."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys


def main():
    folder = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Validar os exemplos novos do kit de preparacao")
    parser.add_argument("--project", type=Path, default=folder.parent)
    args = parser.parse_args()
    project = args.project.resolve()
    if not (project / "quantumtrace" / "__init__.py").is_file():
        print("Copia a pasta Preparacao para a pasta que contem INICIAR_APP.cmd.")
        return 2
    sys.path.insert(0, str(project))
    from quantumtrace import __version__
    from quantumtrace.inventory import scan_path
    from quantumtrace.report import write_reports

    expected_path = folder / "resultados_esperados.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    report = scan_path(folder / "FICHEIROS_NOVOS")
    checks = []
    for source, wanted in expected["cases"].items():
        actual = [
            [f["algorithm"], f["key_bits"], f["risk"], f["observation"]]
            for f in report["findings"] if f["evidence"]["source"] == source
        ]
        passed = Counter(map(tuple, actual)) == Counter(map(tuple, wanted))
        checks.append({"source": source, "passed": passed, "expected": wanted, "actual": actual})
        print(("PASSOU" if passed else "FALHOU") + " - " + source)
    expected_sources = set(expected["cases"])
    actual_sources = {f["source"] for f in report["files"]}
    summary_checks = {
        key: {"expected": value, "actual": report["summary"].get(key),
              "passed": report["summary"].get(key) == value}
        for key, value in expected["expected_summary"].items()
    }
    all_passed = (all(c["passed"] for c in checks)
                  and all(c["passed"] for c in summary_checks.values())
                  and expected_sources == actual_sources)
    out = folder / "resultados"
    out.mkdir(exist_ok=True)
    html, inventory = write_reports(report, out)
    validation = {
        "tool_version": __version__, "generated_at": report["generated_at"],
        "expectations_sha256": hashlib.sha256(expected_path.read_bytes()).hexdigest(),
        "scope": expected["description"], "all_passed": all_passed,
        "same_input_file_set": expected_sources == actual_sources,
        "cases": checks, "summary_checks": summary_checks,
        "summary": report["summary"],
    }
    (out / "validacao.json").write_text(json.dumps(validation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("\n" + str(sum(c["passed"] for c in checks)) + "/" + str(len(checks)) + " exemplos coincidem com as expectativas manuais.")
    print("Isto nao mede a precisao geral nem substitui uma avaliacao independente.")
    print("Relatorio: " + str(html))
    print("Inventario: " + str(inventory))
    if not all_passed:
        print("Consulta resultados/validacao.json. Nao alteres expectativas apenas para obter PASSOU.")
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
