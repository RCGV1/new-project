from __future__ import annotations

import shutil
from pathlib import Path

import olefile

from astro25_decoder.decoder import Astro25Codeplug, _crc16_zero_poly


INPUT_PATH = Path(
    "/Users/benjaminfaershtein/Library/Application Support/Claude/local-agent-mode-sessions/"
    "f305f19d-5c6c-4d61-8cd4-05c15baba217/a7cd1779-ce11-4565-ba97-56928daedd31/"
    "local_a9e60ecf-d4d1-4ff3-9708-ae661053b9a0/uploads/W6SLG XTS25000 Config.cpg"
)
OUTPUT_PATH = Path(
    "/Users/benjaminfaershtein/Documents/New project/generated/"
    "W6SLG XTS25000 Config.modified-label-aapc.cpg"
)

TARGET_SID = 33
TARGET_SLOT = 15
TARGET_LABEL = b"AAPC"
BASE_OFFSET = 27
SLOT_WIDTH = 17


def _encrypt_stream(cp: Astro25Codeplug, sid: int, decrypted: bytes) -> bytes:
    raw = cp.streams[sid]
    if len(raw) != len(decrypted) + 2:
        raise ValueError(f"stream {sid} size mismatch")
    body = bytes(
        decrypted[idx] ^ cp.key[idx] if idx < len(cp.key) else decrypted[idx]
        for idx in range(len(decrypted))
    )
    return raw[:2] + body


def main() -> None:
    cp = Astro25Codeplug(INPUT_PATH)
    decrypted = bytearray(cp.decrypted_streams[TARGET_SID])

    slot_offset = BASE_OFFSET + (TARGET_SLOT - 1) * SLOT_WIDTH
    old_slot = bytes(decrypted[slot_offset : slot_offset + SLOT_WIDTH])
    new_slot = TARGET_LABEL + (b"\x00" * (SLOT_WIDTH - len(TARGET_LABEL)))

    original_tail = int.from_bytes(decrypted[-2:], "big")
    patched = bytearray(decrypted)
    patched[slot_offset : slot_offset + SLOT_WIDTH] = new_slot
    recomputed_tail = _crc16_zero_poly(
        patched[4:-2],
        poly=0x1021,
        refin=False,
        refout=False,
    )
    if recomputed_tail != original_tail:
        raise ValueError(
            f"trial label does not preserve tail: original=0x{original_tail:04x} "
            f"recomputed=0x{recomputed_tail:04x}"
        )

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(INPUT_PATH, OUTPUT_PATH)

    with olefile.OleFileIO(str(OUTPUT_PATH), write_mode=True) as ole:
        ole.write_stream(f"DataStg/Strm_{TARGET_SID}", _encrypt_stream(cp, TARGET_SID, patched))

    verify = Astro25Codeplug(OUTPUT_PATH)
    verified = verify.decrypted_streams[TARGET_SID][slot_offset : slot_offset + SLOT_WIDTH]
    if verified != new_slot:
        raise ValueError("verification failed: patched slot did not round-trip")

    print(f"input={INPUT_PATH}")
    print(f"output={OUTPUT_PATH}")
    print(f"sid={TARGET_SID} slot={TARGET_SLOT}")
    print(f"old_label={old_slot.split(b'\\x00', 1)[0].decode('ascii', 'replace')}")
    print(f"new_label={TARGET_LABEL.decode('ascii')}")
    print(f"tail=0x{original_tail:04x}")


if __name__ == "__main__":
    main()
