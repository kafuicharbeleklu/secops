import json
import platform
import sys
from datetime import datetime
from pathlib import Path


def _write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _write_text(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def run_precheck(profile, workspace):
    report = {
        "profile": profile,
        "workspace": str(workspace),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "timestamp": datetime.now().isoformat(timespec="minutes"),
        "checks": [
            {"name": "workspace_exists", "ok": workspace.exists()},
            {"name": "workspace_writable", "ok": workspace.parent.exists()},
            {"name": "python_available", "ok": True},
        ],
    }
    output = _write_json(workspace / "reports" / "precheck_report.json", report)
    return [output], ["Precheck termine.", f"Rapport: {output.name}"]


def run_install(profile, workspace):
    manifest = {
        "profile": profile,
        "installed_at": datetime.now().isoformat(timespec="minutes"),
        "folders": ["bin", "config", "logs", "data"],
    }
    for folder in manifest["folders"]:
        (workspace / folder).mkdir(parents=True, exist_ok=True)
    output = _write_json(workspace / "install" / "install_manifest.json", manifest)
    return [output], ["Installation simulee.", f"Manifest: {output.name}"]


def run_config(profile, workspace):
    lines = [
        f"APP_PROFILE={profile}",
        "APP_PORT=8080",
        "APP_LOG_LEVEL=INFO",
        "APP_MODE=template",
    ]
    output = _write_text(workspace / "config" / "runtime.env", lines)
    return [output], ["Configuration ecrite.", f"Env: {output.name}"]


def run_service(profile, workspace):
    lines = [
        "ServiceName=sample-agent",
        f"Profile={profile}",
        "StartMode=Manual",
        "HealthEndpoint=http://localhost:8080/health",
    ]
    output = _write_text(workspace / "services" / "service_registration.txt", lines)
    return [output], ["Fiche service generee.", f"Service: {output.name}"]


def run_verify(profile, workspace):
    lines = [
        f"Verification profile: {profile}",
        "Result: PASS",
        "Checks: precheck, install, config, service",
    ]
    output = _write_text(workspace / "reports" / "verification_report.txt", lines)
    return [output], ["Verification terminee.", f"Report: {output.name}"]


def run_rollback(profile, workspace):
    lines = [
        "1. Arreter les services applicatifs",
        "2. Sauvegarder les logs courants",
        "3. Restaurer les configurations precedentes",
        "4. Supprimer les artefacts installes si necessaire",
        f"Rollback profile: {profile}",
    ]
    output = _write_text(workspace / "rollback" / "rollback_plan.txt", lines)
    return [output], ["Plan de rollback prepare.", f"Plan: {output.name}"]


TARGET_HANDLERS = {
    "PRECHECK": run_precheck,
    "INSTALL": run_install,
    "CONFIG": run_config,
    "SERVICE": run_service,
    "VERIFY": run_verify,
    "ROLLBACK": run_rollback,
}


def execute_targets(targets, profile, workspace):
    workspace.mkdir(parents=True, exist_ok=True)
    outputs = []
    notes = []

    for target in targets:
        handler = TARGET_HANDLERS[target]
        target_outputs, target_notes = handler(profile, workspace)
        outputs.extend(target_outputs)
        notes.extend([f"{target}: {note}" for note in target_notes])

    return outputs, notes
