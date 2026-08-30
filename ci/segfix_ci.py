#!/usr/bin/env python3
"""SegFix CI — lanza un escaneo/remediación SegFix desde un pipeline (GitHub Actions / Azure DevOps).

Sin dependencias externas (stdlib): apto para cualquier runner con Python 3.9+.

Uso típico (GitHub Actions):
    env:
      SEGFIX_TOKEN: ${{ secrets.SEGFIX_TOKEN }}
    run: python segfix_ci.py --fail-on high

Uso típico (Azure DevOps):
    env:
      SEGFIX_TOKEN: $(SEGFIX_TOKEN)
    script: python integrations/ci/segfix_ci.py --fail-on high

Qué hace:
  1. Detecta el contexto CI (GitHub Actions / Azure Pipelines): repo, rama, commit, link al run.
  2. POST /api/executions con el PAT (Bearer scfx_...): la ejecución entra al MISMO motor y
     facturación que la consola, etiquetada con su origen (se ve en la consola con badge CI).
  3. Espera el resultado (polling) y muestra el resumen (vulns, remediadas, PR).
  4. Security Gate: sale con código 1 si quedan vulnerabilidades SIN resolver de severidad >= --fail-on.

Códigos de salida: 0 ok/gate aprobado · 1 gate NO aprobado · 2 la ejecución falló · 3 error de uso/config.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
TERMINAL = {"completed", "failed", "needs_review"}


# ---------- contexto CI ----------
def detect_ci() -> dict:
    """Detecta proveedor de CI y arma origen + repo + rama + commit + link al run."""
    env = os.environ
    if env.get("GITHUB_ACTIONS") == "true":
        server = env.get("GITHUB_SERVER_URL", "https://github.com")
        repo = env.get("GITHUB_REPOSITORY", "")
        return {
            "origin": "github",
            "repo_url": f"{server}/{repo}" if repo else "",
            "branch": env.get("GITHUB_HEAD_REF") or env.get("GITHUB_REF_NAME", ""),
            "commit": env.get("GITHUB_SHA", ""),
            "run_url": f"{server}/{repo}/actions/runs/{env.get('GITHUB_RUN_ID', '')}" if repo else "",
        }
    if env.get("TF_BUILD") == "True":
        org = env.get("SYSTEM_COLLECTIONURI", "").rstrip("/")
        proj = env.get("SYSTEM_TEAMPROJECT", "")
        return {
            "origin": "azuredevops",
            "repo_url": env.get("BUILD_REPOSITORY_URI", ""),
            "branch": env.get("BUILD_SOURCEBRANCHNAME", ""),
            "commit": env.get("BUILD_SOURCEVERSION", ""),
            "run_url": f"{org}/{proj}/_build/results?buildId={env.get('BUILD_BUILDID', '')}" if org else "",
        }
    return {"origin": "api", "repo_url": "", "branch": "", "commit": "", "run_url": ""}


# ---------- HTTP ----------
def api(base: str, token: str, method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(
        base.rstrip("/") + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                 "User-Agent": "segfix-ci/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        raise SystemExit(f"::error::SegFix API {e.code} en {path}: {detail}") from None
    except urllib.error.URLError as e:
        raise SystemExit(f"::error::No se pudo conectar a SegFix ({base}): {e.reason}") from None


# ---------- resumen ----------
def summarize(base: str, ex: dict, findings: list[dict], gate_sev: str, gate_pass: bool) -> str:
    """Markdown para el job summary (GitHub) / archivo de resumen (ADO)."""
    unresolved = [f for f in findings if not f.get("resolved")]
    exec_url = f"{base.rstrip('/')}/ejecuciones/{ex['id']}"
    icon = "✅" if gate_pass else "❌"
    lines = [
        f"## {icon} SegFix Security Scan — ejecución [#{ex['id']}]({exec_url})",
        "",
        f"| Vulns encontradas | Remediadas | Acción manual | Sin resolver | Gate (`--fail-on {gate_sev}`) |",
        "|---|---|---|---|---|",
        f"| {ex.get('vulns_found', 0)} | {ex.get('vulns_fixed', 0)} | {ex.get('vulns_manual', 0)} "
        f"| {len(unresolved)} | {'APROBADO ✅' if gate_pass else 'BLOQUEADO ❌'} |",
        "",
    ]
    if ex.get("pr_url"):
        lines.append(f"**Pull Request con los fixes:** {ex['pr_url']}\n")
    if unresolved:
        lines += ["### Vulnerabilidades sin resolver", "", "| Severidad | Dependencia | CVE |", "|---|---|---|"]
        for f in sorted(unresolved, key=lambda x: -SEV_ORDER.get((x.get("severity") or "").lower(), 0))[:20]:
            lines.append(f"| {(f.get('severity') or '?').upper()} | `{f.get('dependency', '?')}` | {f.get('cve_id') or '—'} |")
        lines.append("")
    lines.append(f"_Detalle completo, evidencia y compliance en la [consola SegFix]({exec_url})._")
    return "\n".join(lines)


def write_summary(md: str) -> None:
    gh = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh:
        with open(gh, "a", encoding="utf-8") as f:
            f.write(md + "\n")
    if os.environ.get("TF_BUILD") == "True":   # ADO: subir como summary del build
        path = os.path.join(os.environ.get("BUILD_ARTIFACTSTAGINGDIRECTORY", "."), "segfix-summary.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(md + "\n")
        print(f"##vso[task.uploadsummary]{path}")


def main() -> int:
    p = argparse.ArgumentParser(description="SegFix desde CI (GitHub Actions / Azure DevOps)")
    p.add_argument("--url", default=os.environ.get("SEGFIX_URL", "https://platform.segfix.io"))
    p.add_argument("--token", default=os.environ.get("SEGFIX_TOKEN", ""), help="PAT de SegFix (scfx_...). Cargalo como secret del pipeline.")
    p.add_argument("--repo-url", default="", help="Repo a escanear (default: auto-detectado del CI)")
    p.add_argument("--repo-id", type=int, default=0, help="Repo del registro de proyectos (PAYG); alternativa a --repo-url")
    p.add_argument("--branch", default="", help="Rama (default: auto-detectada del CI)")
    p.add_argument("--fail-on", default="high", choices=["none", "low", "medium", "high", "critical"],
                   help="Rompe el pipeline si quedan vulns SIN resolver de esta severidad o mayor (default high)")
    p.add_argument("--max-wait", type=int, default=1800, help="Segundos máximos de espera (default 1800)")
    p.add_argument("--poll", type=int, default=10, help="Intervalo de polling en segundos (default 10)")
    p.add_argument("--no-wait", action="store_true", help="Lanza y no espera el resultado (sin gate)")
    args = p.parse_args()

    if not args.token:
        print("::error::Falta el PAT de SegFix: seteá SEGFIX_TOKEN (secret del pipeline) o --token")
        return 3

    ci = detect_ci()
    repo_url = args.repo_url or ci["repo_url"]
    branch = args.branch or ci["branch"] or "master"
    if not repo_url and not args.repo_id:
        print("::error::No pude detectar el repo: pasá --repo-url o --repo-id")
        return 3

    body = {"target_branch": branch, "origin": ci["origin"],
            "ci_commit": ci["commit"] or None, "ci_run_url": ci["run_url"] or None}
    if args.repo_id:
        body["repo_id"] = args.repo_id
    else:
        body["repo_url"] = repo_url

    print(f"SegFix ▸ lanzando escaneo de {repo_url or f'repo_id={args.repo_id}'} (rama {branch}) "
          f"desde {ci['origin']}…")
    ex = api(args.url, args.token, "POST", "/api/executions", body)
    exec_url = f"{args.url.rstrip('/')}/ejecuciones/{ex['id']}"
    print(f"SegFix ▸ ejecución #{ex['id']} creada → {exec_url}")

    if args.no_wait:
        print("SegFix ▸ --no-wait: no se espera el resultado (sin gate).")
        return 0

    t0 = time.time()
    while ex.get("status") not in TERMINAL:
        if time.time() - t0 > args.max_wait:
            print(f"::error::SegFix: timeout a los {args.max_wait}s (ejecución #{ex['id']} sigue '{ex.get('status')}')")
            return 2
        time.sleep(max(2, args.poll))
        ex = api(args.url, args.token, "GET", f"/api/executions/{ex['id']}")
        print(f"SegFix ▸ estado: {ex.get('status')} · fase: {ex.get('state')} "
              f"({int(time.time() - t0)}s)", flush=True)

    findings = ex.get("findings") or []
    if ex.get("status") == "failed":
        md = summarize(args.url, ex, findings, args.fail_on, False)
        write_summary(md)
        print(f"::error::SegFix: la ejecución #{ex['id']} FALLÓ. Detalle: {exec_url}")
        return 2

    # ---- Security Gate: vulns sin resolver con severidad >= umbral (excepciones ya vienen aplicadas) ----
    gate_pass = True
    if args.fail_on != "none":
        threshold = SEV_ORDER[args.fail_on]
        blockers = [f for f in findings
                    if not f.get("resolved") and SEV_ORDER.get((f.get("severity") or "").lower(), 0) >= threshold]
        gate_pass = not blockers

    md = summarize(args.url, ex, findings, args.fail_on, gate_pass)
    write_summary(md)
    print()
    print(f"SegFix ▸ encontradas={ex.get('vulns_found', 0)} remediadas={ex.get('vulns_fixed', 0)} "
          f"manual={ex.get('vulns_manual', 0)} pr={ex.get('pr_url') or '—'}")
    if not gate_pass:
        print(f"::error::Security Gate BLOQUEADO: quedan vulns sin resolver de severidad >= {args.fail_on}. {exec_url}")
        return 1
    print(f"SegFix ▸ Security Gate APROBADO ✅ · {exec_url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
