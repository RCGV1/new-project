from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

ROOT = Path("/Users/benjaminfaershtein/Documents/New project")
sys.path.insert(0, str(ROOT / "src"))

from astro25_decoder.decoder import load_codeplug
from astro25_decoder.writer import write_channel

GENERATED = ROOT / "generated"


def diff_streams(first: Path, second: Path) -> list[tuple[int, str, int]]:
    left = load_codeplug(first)
    right = load_codeplug(second)
    changed = []
    for sid in sorted(set(left.streams) | set(right.streams)):
        a = left.decrypted_streams.get(sid)
        b = right.decrypted_streams.get(sid)
        if a != b:
            header = (left.streams.get(sid) or right.streams.get(sid))[:2].hex()
            diffcount = sum(x != y for x, y in zip(a or b"", b or b"")) + abs(
                len((a or b"")) - len((b or b""))
            )
            changed.append((sid, header, diffcount))
    return changed


def main() -> None:
    GENERATED.mkdir(parents=True, exist_ok=True)

    aapc_out = GENERATED / "validation_test_aapc.cpg"
    write_channel(
        "/Users/benjaminfaershtein/Library/Application Support/Claude/local-agent-mode-sessions/"
        "f305f19d-5c6c-4d61-8cd4-05c15baba217/a7cd1779-ce11-4565-ba97-56928daedd31/"
        "local_a9e60ecf-d4d1-4ff3-9708-ae661053b9a0/uploads/W6SLG XTS25000 Config.cpg",
        aapc_out,
        zone=1,
        slot=15,
        label="AAPC",
        touch_save_metadata=False,
    )
    print(
        "AAPC label-only diff:",
        diff_streams(
            aapc_out,
            GENERATED / "W6SLG XTS25000 Config.modified-label-aapc.cpg",
        ),
    )

    pl77_out = GENERATED / "validation_test_pl77.cpg"
    write_channel(
        "/Users/benjaminfaershtein/Downloads/H18KEF9PW6AN_100004-000002-2.cpg",
        pl77_out,
        zone=1,
        slot=1,
        tx_pl_hz=77.0,
        save_datetime=datetime(2026, 4, 6, 17, 1),
    )
    print(
        "Single-zone TX PL 77.0 diff:",
        diff_streams(
            pl77_out,
            Path("/Users/benjaminfaershtein/Downloads/H18KEF9PW6AN_100004-000002-2 (2).cpg"),
        ),
    )

    codex_out = GENERATED / "validation_test_codex_from_aapc.cpg"
    write_channel(
        GENERATED / "W6SLG XTS25000 Config.modified-label-aapc.cpg",
        codex_out,
        zone=1,
        slot=1,
        label="Codex",
        rx_mhz=146.6,
        tx_mhz=142.2,
        tx_pl_hz=146.2,
        save_datetime=datetime(2026, 4, 6, 16, 47),
    )
    print(
        "W6SLG Codex from AAPC diff:",
        diff_streams(
            codex_out,
            Path("/Users/benjaminfaershtein/Downloads/W6SLG XTS25000 Config.modified-label-aapc (1).cpg"),
        ),
    )


if __name__ == "__main__":
    main()
