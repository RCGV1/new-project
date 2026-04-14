# macOS Privileged Binaries PoC Guide

This guide turns the audit findings into reproducible validation steps that are safe to run on a researcher-owned Mac.

Primary runner:

```bash
python3 "/Users/benjaminfaershtein/Documents/New project/scripts/macos_privileged_pocs.py" --help
```

Artifacts are written under:

[`/Users/benjaminfaershtein/Documents/New project/generated/security_pocs`](/Users/benjaminfaershtein/Documents/New%20project/generated/security_pocs)

## Coverage

| Finding | PoC type | What it proves | What it does not prove |
|---|---|---|---|
| `authopen` TOCTOU | Interactive runtime | Whether post-auth `open()` follows a swapped symlink target | Full privilege escalation to arbitrary protected files |
| `authopen` decoy SQLite | Interactive runtime | Whether the same race can reach a harmless SQLite-shaped target | Access to any real protected privacy store |
| `authopen` differential proof pack | Interactive runtime | Whether the same visible bait path produces different returned content with and without a swap | Direct access to real privileged files |
| `at` OLDPWD injection | Static by default, optional runtime wait | Whether `OLDPWD` is written raw into the generated shell script | Root code execution |
| `at` incomplete env filter | Static | Whether `IFS`/`PATH` survive into the generated script on this build | A live exploit chain |
| `atrun` spool enumeration | Runtime metadata check | Whether any local user can decode job schedule metadata from filenames | Access to job contents |
| `security_authtrampoline` | Caller discovery | Which local apps appear to reference deprecated `AuthorizationExecuteWithPrivileges` behavior | An exploit against the trampoline itself |
| disclosure report | Local reporting | Collates latest evidence into a markdown status update | Independent exploitation evidence |

## 1. `authopen` TOCTOU

Use this to validate the reported race without touching any system-owned target. The PoC creates two unreadable lab files:

- `gate.txt`
- `payload.txt`

It then launches [`/usr/libexec/authopen`](/usr/libexec/authopen) on `gate.txt`, waits for the authorization dialog, and swaps `gate.txt` to a symlink pointing at `payload.txt`.

If the bug is real in the way the audit describes, `authopen` should return the payload marker rather than the original gate marker.

Dry run:

```bash
python3 "/Users/benjaminfaershtein/Documents/New project/scripts/macos_privileged_pocs.py" authopen-toctou --dry-run
```

Interactive run:

```bash
python3 "/Users/benjaminfaershtein/Documents/New project/scripts/macos_privileged_pocs.py" authopen-toctou
```

Interpretation:

- `Confirmed payload marker after swap: yes`
  Strong confirmation that the privileged open followed the swapped target.
- `Confirmed payload marker after swap: no`
  This run did not reproduce the issue. That can mean the bug is not present, the swap timing missed the window, or the authorization step was not reached as expected.

## 1b. `authopen` Decoy SQLite Variant

This variant keeps the same race structure but swaps to a harmless local SQLite database rather than a plain text payload. It is meant to demonstrate database-like impact without touching a real protected store.

Dry run:

```bash
python3 "/Users/benjaminfaershtein/Documents/New project/scripts/macos_privileged_pocs.py" authopen-decoy-sqlite --dry-run
```

Interactive run:

```bash
python3 "/Users/benjaminfaershtein/Documents/New project/scripts/macos_privileged_pocs.py" authopen-decoy-sqlite
```

Expected confirmation:

- `Confirmed SQLite header after swap: yes`

That means the post-auth `open()` followed the swapped target and returned a decoy SQLite header (`SQLite format 3`) instead of the bait file.

## 1c. `authopen` Differential Proof Pack

This is the cleanest reviewer-facing demonstration. It runs two interactive phases against the same visible bait path:

1. control run with no swap
2. raced run with a swap

If phase 1 returns bait content and phase 2 returns payload content, the artifact set shows a classic object-mismatch TOCTOU without touching a real privileged file.

Dry run:

```bash
python3 "/Users/benjaminfaershtein/Documents/New project/scripts/macos_privileged_pocs.py" authopen-proof-pack --dry-run
```

Interactive run:

```bash
python3 "/Users/benjaminfaershtein/Documents/New project/scripts/macos_privileged_pocs.py" authopen-proof-pack
```

Key artifact:

- `proof_pack.md` under the generated proof-pack directory

This is the recommended packet for a disclosure appendix because it demonstrates:

- same visible bait path
- same approval flow
- different returned object only when the swap is introduced

## 2. `at` OLDPWD Injection

This PoC schedules a temporary `at` job with an `OLDPWD` value that contains a second command. It then reads the generated job script back with `at -c`.

Command:

```bash
python3 "/Users/benjaminfaershtein/Documents/New project/scripts/macos_privileged_pocs.py" at-oldpwd
```

Optional runtime wait:

```bash
python3 "/Users/benjaminfaershtein/Documents/New project/scripts/macos_privileged_pocs.py" at-oldpwd --wait-seconds 180
```

Expected confirmation:

- `job_script.sh` contains a line of the form:

```sh
OLDPWD=/tmp; /usr/bin/id > ...; export OLDPWD
```

That confirms the raw shell-injection behavior described in the audit. If `atrun` is enabled and the runtime wait succeeds, the marker file also confirms the injected command actually ran as the submitting user.

## 3. `at` Environment Filter Gap

This check verifies which variables survive serialization into the generated job script on this macOS build.

Command:

```bash
python3 "/Users/benjaminfaershtein/Documents/New project/scripts/macos_privileged_pocs.py" at-env
```

What to look for:

- `IFS serialized into job script: yes`
- `PATH serialized into job script: yes`

`DYLD_*` may show `no` even though the source-side denylist omits them. That is expected on current macOS because `/usr/bin/at` is setuid-root and the kernel strips `DYLD_*` before the program receives them.

## 4. `atrun` Spool Enumeration

This decodes the world-enumerable job filenames into queue and scheduled timestamp metadata.

Command:

```bash
python3 "/Users/benjaminfaershtein/Documents/New project/scripts/macos_privileged_pocs.py" spool-enum
```

This confirms the informational leakage the audit described:

- queue letter
- 5-hex job number
- 8-hex minutes-since-epoch scheduling value

## 5. `security_authtrampoline` Follow-On

This is not an exploit PoC. It is a scoping aid for the audit recommendation to enumerate callers still using deprecated `AuthorizationExecuteWithPrivileges`.

Command:

```bash
python3 "/Users/benjaminfaershtein/Documents/New project/scripts/macos_privileged_pocs.py" authexec-scan
```

You can narrow the scan:

```bash
python3 "/Users/benjaminfaershtein/Documents/New project/scripts/macos_privileged_pocs.py" authexec-scan --roots /Applications
```

Each hit is a candidate for deeper manual review:

- verify the executable path it passes
- check whether the path is absolute
- confirm whether it constrains arguments and environment

## 6. Disclosure Report

This command turns the latest local artifact set into a markdown status report suitable for notes or responsible disclosure prep.

Command:

```bash
python3 "/Users/benjaminfaershtein/Documents/New project/scripts/macos_privileged_pocs.py" disclosure-report
```

The report includes:

- latest `authopen` lab result
- latest decoy SQLite result
- latest `at` findings
- latest spool enumeration state
- latest deprecated API caller list

## Not Included

I did not turn the following into direct exploit PoCs:

- `at` `creat()` mode misuse: it is a code defect, but the audit already explains why it does not appear to cross a security boundary.
- `security_authtrampoline` arbitrary-root-exec behavior: that API is inherently sensitive, but a direct exploit script would be unnecessarily risky compared with enumerating the callers that expose it.
- any proof-of-concept against the real `TCC.db`: the SQLite variant intentionally stays on a decoy database under the generated lab directory.

## Cleanup Notes

- The `at-*` commands remove their temporary jobs unless `--keep-job` is passed.
- All generated artifacts stay under:
  [`/Users/benjaminfaershtein/Documents/New project/generated/security_pocs`](/Users/benjaminfaershtein/Documents/New%20project/generated/security_pocs)
