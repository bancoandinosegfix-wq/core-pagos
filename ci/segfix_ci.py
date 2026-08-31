#!/usr/bin/env python3
"""SegFix CI — lanza un escaneo/remediación SegFix desde un pipeline (GitHub Actions / Azure DevOps).

Sin dependencias externas (stdlib): apto para cualquier runner con Python 3.9+.

Uso típico (GitHub Actions):
    env:
      SEGFIX_TOKEN: ${{ secrets.SEGFIX_TOKEN }}
    run: python segfix_ci.py

Uso típico (Azure DevOps):
    env:
      SEGFIX_TOKEN: $(SEGFIX_TOKEN)
    script: python integrations/ci/segfix_ci.py

Qué hace:
  1. Detecta el contexto CI (GitHub Actions / Azure Pipelines): repo, rama, commit, link al run.
  2. POST /api/executions con el PAT (Bearer scfx_...): la ejecución entra al MISMO motor y
     facturación que la consola, etiquetada con su origen (se ve en la consola con badge CI).
  3. Espera el resultado (polling) y muestra el resumen (vulns, remediadas, PR).
  4. Security Gate: el veredicto lo da SegFix según el PERFIL de seguridad asignado al repo o a su
     proyecto, así la política no se repite en el YAML de cada repositorio. Sale con código 1 si el
     gate no pasa. `--fail-on <sev>` fuerza un umbral y pisa el perfil (override de emergencia).

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
SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}


def _abierto(f: dict) -> bool:
    """Riesgo vivo: ni remediado ni exceptuado (falso positivo / riesgo aceptado con vencimiento)."""
    return not f.get("resolved") and not f.get("exception")


def _blockers(findings: list[dict], gate_sev: str) -> list[dict]:
    """Hallazgos abiertos que superan el umbral: son los que frenan el despliegue."""
    if gate_sev == "none":
        return []
    thr = SEV_ORDER[gate_sev]
    return [f for f in findings
            if _abierto(f) and SEV_ORDER.get((f.get("severity") or "").lower(), 0) >= thr]


def _perfil_linea(g: dict | None) -> str:
    """'Estricto (heredado de Core Bancario)' — de dónde sale la política que se aplicó."""
    if not g or not g.get("profile_name"):
        return ""
    origen = {"repo": "propio del repositorio", "proyecto": "heredado del proyecto",
              "empresa": "por defecto de la empresa", "base": "base de SegFix"}.get(g.get("origen"), "")
    det = g.get("origen_detalle")
    if det and g.get("origen") == "proyecto":
        origen = f"heredado de {det}"
    return f"{g['profile_name']}" + (f" ({origen})" if origen else "")


def _score_line(sc: dict | None) -> str:
    """'72/100 (C)' — el score que publica la API para esta ejecución."""
    if not sc:
        return ""
    return f"{sc.get('score')}/100 ({sc.get('letra')})"


def summarize(base: str, ex: dict, findings: list[dict], gate_sev: str, gate_pass: bool) -> str:
    """Reporte para el equipo que mira el pipeline: qué resolvió SegFix, qué falta y qué hacer ahora."""
    b = base.rstrip("/")
    exec_url = f"{b}/ejecuciones/{ex['id']}"
    unresolved = [f for f in findings if not f.get("resolved")]
    blockers = _blockers(findings, gate_sev)
    found, fixed = ex.get("vulns_found", 0) or 0, ex.get("vulns_fixed", 0) or 0
    manual = ex.get("vulns_manual", 0) or 0
    pct = round(fixed / found * 100) if found else 0

    lines = [f"## 🛡️ SegFix · Análisis de seguridad del código", ""]

    # Titular: lo que SegFix HIZO (esto es lo primero que se lee).
    if fixed:
        lines.append(f"> **SegFix remedió {fixed} de {found} vulnerabilidades automáticamente ({pct}%)** "
                     f"y dejó el cambio listo para revisar.")
    elif found:
        lines.append(f"> **SegFix analizó el repositorio y encontró {found} vulnerabilidades.**")
    else:
        lines.append("> **SegFix analizó el repositorio y no encontró vulnerabilidades.** ✅")
    sc = ex.get("scoring") or {}
    exceptuados = sc.get("exceptuados", 0)
    cols = ["Score de seguridad", "Encontradas", "Remediadas por IA", "Requieren acción manual", "Bloquean el despliegue"]
    vals = [f"**{_score_line(sc) or '—'}**", f"**{found}**", f"**{fixed}**", str(manual), str(len(blockers))]
    if exceptuados:
        cols.insert(4, "Exceptuadas")
        vals.insert(4, str(exceptuados))
    lines += ["",
              "| " + " | ".join(cols) + " |",
              "|" + ":--:|" * len(cols),
              "| " + " | ".join(vals) + " |", ""]
    if sc:
        lines += [f"<sub>El score parte de 100 y descuenta por cada vulnerabilidad que queda abierta "
                  f"(crítica −{sc.get('pesos', {}).get('critical', 25)}, alta −{sc.get('pesos', {}).get('high', 10)}, "
                  f"media −{sc.get('pesos', {}).get('medium', 4)}, baja −{sc.get('pesos', {}).get('low', 1)}). "
                  f"Lo remediado y lo exceptuado no descuentan.</sub>", ""]

    if ex.get("pr_url"):
        lines += [f"### ✅ Pull Request listo para revisar", "",
                  f"SegFix abrió un PR con las correcciones aplicadas y validadas: **{ex['pr_url']}**", ""]
    elif ex.get("push_error"):
        # Las correcciones existen pero no llegaron al repo: es un problema de ENTREGA (credenciales,
        # permisos), no del análisis. Decirlo así evita que se lea como "SegFix no pudo arreglarlo".
        lines += ["### ⚠️ Las correcciones no se pudieron entregar", "",
                  f"SegFix generó las correcciones, pero **no pudo escribir en el repositorio**, así que "
                  f"todavía no hay Pull Request y los hallazgos siguen abiertos.", "",
                  "```", str(ex["push_error"]).strip()[:400], "```", "",
                  f"Revisá las credenciales del repositorio en la consola y volvé a correr el pipeline "
                  f"→ [Abrir la ejecución #{ex['id']}]({exec_url})", ""]

    # Veredicto del gate, con el porqué en lenguaje de negocio.
    if gate_pass:
        lines += ["### 🚦 Security Gate: **APROBADO**", "",
                  f"No quedan vulnerabilidades de severidad `{gate_sev}` o superior. El despliegue puede continuar.", ""]
    else:
        lines += ["### 🚦 Security Gate: **BLOQUEADO**", "",
                  f"El despliegue se detuvo porque quedan **{len(blockers)} "
                  f"{'vulnerabilidad' if len(blockers) == 1 else 'vulnerabilidades'} "
                  f"de severidad `{gate_sev}` o superior** sin resolver.", "",
                  "| | Severidad | Componente | CVE | Detalle |", "|:--:|---|---|---|---|"]
        for f in sorted(blockers, key=lambda x: -SEV_ORDER.get((x.get("severity") or "").lower(), 0))[:20]:
            sev = (f.get("severity") or "?").lower()
            cve = f.get("cve_id") or ""
            cve_txt = f"[{cve}](https://nvd.nist.gov/vuln/detail/{cve})" if cve else "—"
            lines.append(f"| {SEV_ICON.get(sev, '⚪')} | **{sev.upper()}** | `{f.get('dependency', '?')}` "
                         f"| {cve_txt} | [Ver en SegFix]({exec_url}) |")
        if len(blockers) > 20:
            lines.append(f"| | | _y {len(blockers) - 20} más_ | | [Ver todas]({exec_url}) |")
        lines += ["",
                  "#### ¿Qué sigue?", "",
                  f"1. **Revisá el detalle** de cada hallazgo → [Abrir la ejecución #{ex['id']} en SegFix]({exec_url})",
                  "2. **¿Es un falso positivo o un riesgo aceptado?** Excepcionalo desde la consola con "
                  "justificación y fecha de compromiso de revisión.",
                  "3. **Volvé a correr el pipeline**: con las excepciones aplicadas el gate pasa y el despliegue sigue.", ""]

    if manual:
        lines += [f"> ℹ️ {manual} "
                  f"{'hallazgo requiere' if manual == 1 else 'hallazgos requieren'} una decisión humana por diseño "
                  "(por ejemplo, rotar un secreto): no son una falla del análisis.", ""]

    lines.append(f"---")
    lines.append(f"📊 Evidencia, SBOM y reporte de compliance de esta ejecución: **[consola de SegFix]({exec_url})**")
    return "\n".join(lines)


def write_outputs(base: str, ex: dict, findings: list[dict], gate_sev: str, gate_pass: bool) -> None:
    """Expone el resultado como outputs del job, para que el Security Gate arme su propio mensaje."""
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    blockers = _blockers(findings, gate_sev)
    top = sorted(blockers, key=lambda x: -SEV_ORDER.get((x.get("severity") or "").lower(), 0))[:5]
    resumen = "; ".join(f"{(f.get('severity') or '?').upper()} {f.get('dependency', '?')}"
                        f"{' (' + f['cve_id'] + ')' if f.get('cve_id') else ''}" for f in top)
    sc = ex.get("scoring") or {}
    vals = {
        "score": sc.get("score", ""),
        "score_letra": sc.get("letra", ""),
        "excepted": sc.get("exceptuados", 0),
        "exec_id": ex["id"],
        "exec_url": f"{base.rstrip('/')}/ejecuciones/{ex['id']}",
        "found": ex.get("vulns_found", 0) or 0,
        "fixed": ex.get("vulns_fixed", 0) or 0,
        "manual": ex.get("vulns_manual", 0) or 0,
        "blockers": len(blockers),
        "blockers_top": resumen,
        "pr_url": ex.get("pr_url") or "",
        "gate": "pass" if gate_pass else "block",
        "threshold": gate_sev,
        "profile": (ex.get("gate") or {}).get("profile_name", ""),
        "profile_origin": _perfil_linea(ex.get("gate")),
        # Las correcciones no llegaron al repo (credenciales/permisos): el gate lo aclara aparte,
        # porque la causa NO es que la IA no haya podido corregir.
        "push_error": str(ex.get("push_error") or "").strip().replace("\n", " ")[:200],
    }
    with open(path, "a", encoding="utf-8") as f:
        for k, v in vals.items():
            f.write(f"{k}={v}\n")


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
    p.add_argument("--fail-on", default="auto", choices=["auto", "none", "low", "medium", "high", "critical"],
                   help="Umbral que rompe el pipeline. Por defecto 'auto': manda el PERFIL de seguridad "
                        "asignado al repo/proyecto en SegFix. Un valor explícito lo pisa (override).")
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
        write_outputs(args.url, ex, findings, args.fail_on, False)
        print(f"::error::SegFix no pudo completar el análisis (ejecución #{ex['id']}). "
              f"Revisá el detalle y el motivo en {exec_url}")
        return 2

    # ---- Security Gate ----
    # El veredicto lo da el SERVIDOR, según el perfil de seguridad asignado a ese repo o proyecto:
    # así la política vive en SegFix y no repetida en el YAML de cada repositorio. El `--fail-on`
    # queda solo como override de emergencia, o para cuando el servidor todavía no manda perfil.
    g = ex.get("gate") or {}
    if g and args.fail_on == "auto":
        gate_sev = g.get("fail_on") or "high"
        gate_pass = bool(g.get("passed"))
    else:
        gate_sev = "high" if args.fail_on == "auto" else args.fail_on
        gate_pass = not _blockers(findings, gate_sev)
    blockers = _blockers(findings, gate_sev)

    md = summarize(args.url, ex, findings, gate_sev, gate_pass)
    write_summary(md)
    write_outputs(args.url, ex, findings, gate_sev, gate_pass)

    found, fixed = ex.get("vulns_found", 0) or 0, ex.get("vulns_fixed", 0) or 0
    sc = ex.get("scoring") or {}
    print()
    if g.get("profile_name"):
        print(f"SegFix ▸ Perfil aplicado: {_perfil_linea(g)} — frena desde {gate_sev}"
              + (f", score mínimo {g['min_score']}" if g.get("min_score") else ""))
    if sc:
        print(f"SegFix ▸ Score de seguridad: {_score_line(sc)}"
              + (f" · {sc['exceptuados']} exceptuadas" if sc.get("exceptuados") else ""))
    print(f"SegFix ▸ {fixed} de {found} vulnerabilidades remediadas automáticamente"
          + (f" · {ex.get('vulns_manual')} requieren acción manual" if ex.get("vulns_manual") else ""))
    if ex.get("pr_url"):
        print(f"SegFix ▸ Pull Request con los fixes: {ex['pr_url']}")
    elif ex.get("push_error"):
        print(f"::warning title=SegFix no pudo entregar las correcciones::Las correcciones se generaron "
              f"pero no se pudieron escribir en el repositorio, así que no hay Pull Request. "
              f"Motivo: {str(ex['push_error']).strip()[:200]}")
    print(f"SegFix ▸ Detalle de la ejecución: {exec_url}")

    if not gate_pass:
        top = "; ".join(f"{(f.get('severity') or '?').upper()} {f.get('dependency', '?')}" for f in blockers[:3])
        print()
        sc_txt = f"Score {_score_line(sc)}. " if sc else ""
        print(f"::error title=Security Gate bloqueado por SegFix::{sc_txt}Quedan {len(blockers)} "
              f"vulnerabilidades de severidad {gate_sev} o superior sin resolver ({top}). "
              f"Revisalas en {exec_url} — si alguna es un falso positivo, excepcionala con "
              f"justificación y fecha de revisión, y volvé a correr el pipeline.")
        return 1
    print(f"SegFix ▸ Security Gate APROBADO ✅ — no quedan vulnerabilidades de severidad {gate_sev} o superior.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
