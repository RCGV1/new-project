from __future__ import annotations

import re
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import olefile

CTCSS = [
    0,
    67.0,
    69.3,
    71.9,
    74.4,
    77.0,
    79.7,
    82.5,
    85.4,
    88.5,
    91.5,
    94.8,
    97.4,
    100.0,
    103.5,
    107.2,
    110.9,
    114.8,
    118.8,
    123.0,
    127.3,
    131.8,
    136.5,
    141.3,
    146.2,
    151.4,
    156.7,
    159.8,
    162.2,
    165.5,
    167.9,
    171.3,
    173.8,
    177.3,
    179.9,
    183.5,
    186.2,
    189.9,
    192.8,
    196.6,
    199.5,
    203.5,
    206.5,
    210.7,
    218.1,
    225.7,
    229.1,
    233.6,
    241.8,
    250.3,
    254.1,
]

HEADER_NAMES = {
    "9b3f": "directory",
    "9b3e": "radio_identity",
    "9b3c": "codeplug_serial",
    "8b7d": "version",
    "84c1": "personality",
    "84c4": "zone_label_companion",
    "84c5": "channel_name",
    "84c6": "zone_mapping_companion",
    "84cd": "channel_config_a",
    "84cf": "channel_config_b",
    "84f0": "channel_config_c",
    "8495": "channel_config_d",
    "8489": "channel_config_e",
    "848e": "tone_block",
    "8494": "tone_aux",
    "84f7": "scan_list_member",
    "84f4": "phone_slot_text",
    "8490": "message_slot_text",
    "8491": "username_slot_text",
    "84ce": "call_slot_text_a",
    "84fd": "call_slot_text_b",
    "848a": "call_slot_text_c",
    "84c2": "talkgroup_slot_text",
    "84ca": "zone_config_a",
    "84cb": "zone_config_b",
    "8b61": "message_zones",
    "8b63": "status_zones",
    "8b21": "channel_group",
    "84f8": "support_index_table_a",
    "84fb": "support_index_table_b",
    "8b60": "support_descriptor_a",
    "8b62": "support_descriptor_b",
    "8b71": "support_descriptor_c",
    "8b23": "support_descriptor_d",
    "8b2c": "support_descriptor_e",
    "8b09": "support_descriptor_f",
    "8b30": "support_payload_a",
    "8b31": "support_payload_b",
    "8b36": "support_payload_c",
    "8b72": "support_payload_d",
    "8b76": "list_slot_text_a",
    "8b75": "list_slot_text_b",
    "8b54": "list_slot_text_c",
    "8b56": "list_slot_text_d",
    "8b73": "scan_group",
    "849b": "zone_personality_table",
}

SUPPORT_CLUSTER_HEADERS = {
    "84f8",
    "84fb",
    "8b60",
    "8b62",
    "8b71",
    "8b23",
    "8b2c",
    "8b09",
    "8b30",
    "8b31",
    "8b36",
    "8b72",
}

KNOWN_HEADERS = set(HEADER_NAMES)
MODEL_RE = re.compile(rb"H[A-Z0-9]{11,24}")
SERIAL_RE = re.compile(rb"[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]")
VERSION_RE = re.compile(rb"\d{2}_\d{2}_\d{2}[^\x00]{0,40}")
PRINTABLE_ASCII_RE = re.compile(rb"[ -~]{6,}")
NUMBERED_TEXT_RE = re.compile(r"^(STATUS|MESSAGE) (\d+)$")
COMMON_CRC16_VARIANTS = {
    "arc": {"poly": 0x8005, "init": 0x0000, "xorout": 0x0000, "refin": True, "refout": True},
    "modbus": {"poly": 0x8005, "init": 0xFFFF, "xorout": 0x0000, "refin": True, "refout": True},
    "usb": {"poly": 0x8005, "init": 0xFFFF, "xorout": 0xFFFF, "refin": True, "refout": True},
    "ccitt_false": {"poly": 0x1021, "init": 0xFFFF, "xorout": 0x0000, "refin": False, "refout": False},
    "xmodem": {"poly": 0x1021, "init": 0x0000, "xorout": 0x0000, "refin": False, "refout": False},
    "kermit": {"poly": 0x1021, "init": 0x0000, "xorout": 0x0000, "refin": True, "refout": True},
    "x25": {"poly": 0x1021, "init": 0xFFFF, "xorout": 0xFFFF, "refin": True, "refout": True},
    "aug_ccitt": {"poly": 0x1021, "init": 0x1D0F, "xorout": 0x0000, "refin": False, "refout": False},
    "genibus": {"poly": 0x1021, "init": 0xFFFF, "xorout": 0xFFFF, "refin": False, "refout": False},
    "dnp": {"poly": 0x3D65, "init": 0x0000, "xorout": 0xFFFF, "refin": True, "refout": True},
}


def decode_freq(value: int) -> float:
    return (127000 + value * 5) / 1000


def encode_freq(mhz: float) -> int:
    return round((mhz * 1000 - 127000) / 5)


def _decode_ascii_blob(data: bytes) -> str:
    raw = data.split(b"\x00")[0]
    return raw.decode("ascii", "replace").strip()


def _decode_ascii_slot(data: bytes, offset: int, width: int) -> str:
    return _decode_ascii_blob(data[offset : offset + width])


def _extract_label_frequency_mhz(text: str | None) -> float | None:
    if not text:
        return None
    match = re.search(r"\b(1[34]\d\.\d{3})\b", text)
    return float(match.group(1)) if match else None


def _slot_non_ascii_bytes(data: bytes, offset: int, width: int) -> list[dict[str, int]]:
    rows = []
    for relative_offset, value in enumerate(data[offset : offset + width]):
        if value == 0 or 32 <= value <= 126:
            continue
        rows.append(
            {
                "relative_offset": relative_offset,
                "absolute_offset": offset + relative_offset,
                "value": value,
            }
        )
    return rows


def _extract_printable_ascii_runs(data: bytes) -> list[str]:
    runs = []
    for match in PRINTABLE_ASCII_RE.finditer(data):
        text = match.group(0).decode("ascii", "replace").strip()
        if text:
            runs.append(text)
    return runs


def _guess_band_name(raw_band: int, rx_mhz: float) -> str:
    band_names = {0x41: "VHF-A", 0x43: "VHF-C", 0x81: "UHF"}
    if raw_band in band_names:
        return band_names[raw_band]
    if rx_mhz < 174:
        return f"VHF?(0x{raw_band:02x})"
    return f"UHF?(0x{raw_band:02x})"


def _decode_directory_extra(extra: int) -> dict[str, object]:
    extra_hi = (extra >> 8) & 0xFF
    extra_lo = extra & 0xFF
    if extra_hi == 0x0F:
        return {"kind": "frequency", "value": decode_freq(extra), "display": f"{decode_freq(extra):.3f} MHz"}
    if extra_hi == 0x00 and extra_lo <= 50:
        if extra_lo == 0:
            return {"kind": "ctcss", "value": 0, "display": "No tone"}
        return {"kind": "ctcss", "value": CTCSS[extra_lo], "index": extra_lo, "display": f"{CTCSS[extra_lo]:.1f} Hz"}
    return {"kind": "unknown", "value": extra, "display": f"0x{extra:04x}"}


def _reflect_bits(value: int, width: int) -> int:
    reflected = 0
    for bit in range(width):
        if value & (1 << bit):
            reflected |= 1 << (width - 1 - bit)
    return reflected


def _crc16_variant(
    data: bytes,
    *,
    poly: int,
    init: int,
    xorout: int,
    refin: bool,
    refout: bool,
) -> int:
    crc = init & 0xFFFF
    if refin:
        reflected_poly = _reflect_bits(poly, 16)
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ reflected_poly
                else:
                    crc >>= 1
    else:
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ poly) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
    if refin != refout:
        crc = _reflect_bits(crc, 16)
    return (crc ^ xorout) & 0xFFFF


def _crc16_zero_poly(data: bytes, poly: int, refin: bool, refout: bool) -> int:
    return _crc16_variant(
        data,
        poly=poly,
        init=0x0000,
        xorout=0x0000,
        refin=refin,
        refout=refout,
    )


def _guess_tx_frequency(rx_mhz: float, band: str, band_variant: int) -> float:
    if band_variant in {0x71, 0x74}:
        return rx_mhz
    if band.startswith("UHF"):
        return rx_mhz + 5.0
    return rx_mhz + 0.6


def _format_sid_reference(cp: "Astro25Codeplug", sid: int) -> dict[str, object]:
    raw = cp.streams.get(sid)
    header = raw[:2].hex() if raw else "????"
    return {
        "sid": sid,
        "header": header,
        "header_name": HEADER_NAMES.get(header, "missing") if raw else "missing",
    }


def _classify_ref_group(header: str) -> str:
    if header in {"84c1", "84f7", "84cd", "84cf", "84f0", "8495", "8489", "848e", "8494"}:
        return "channel"
    if header in SUPPORT_CLUSTER_HEADERS:
        return "support"
    if header in {"84c4", "84c5", "84c6", "84c7", "84ca", "84cb", "849b"}:
        return "zone"
    if header in {"8b21", "8b61", "8b63", "8490", "8491"}:
        return "text_or_group"
    if header in {"9b3f", "9b3e", "9b3c", "8b7d"}:
        return "metadata"
    return "other"


def _decode_u32_freq_candidate(value: int) -> dict[str, object]:
    masked = value & 0x7FFFFFFF
    mhz = masked * 5 / 1_000_000
    valid = 130.0 <= mhz <= 180.0 or 380.0 <= mhz <= 520.0
    return {
        "raw": value,
        "masked": masked,
        "flag_high_bit": bool(value & 0x80000000),
        "mhz": mhz if valid else None,
        "is_exact_5khz_step": valid and masked % 1000 == 0,
    }


def _encode_u32_freq_value(mhz: float) -> int:
    return round(mhz * 200_000)


def _infer_c7_profile_hint(
    *,
    block_class: str,
    flags_hex: str,
    freq_values: list[dict[str, object]],
) -> str | None:
    if block_class != "standard":
        return None
    mhz_values = [row["mhz"] for row in freq_values if row["mhz"] is not None]
    if not mhz_values:
        return None
    unique = {round(mhz, 6) for mhz in mhz_values}
    if len(unique) == 1:
        if flags_hex == "00 00 00":
            return "simplex_analog_like"
        if flags_hex == "00 00 01":
            return "simplex_digital_like"
        if flags_hex == "0d 00 0d":
            return "simplex_packet_like"
    if len(mhz_values) >= 3 and round(mhz_values[1], 6) == round(mhz_values[2], 6):
        if flags_hex == "0b 00 0b":
            return "split_pair_like"
        return "paired_frequency_like"
    return None


def _infer_c7_frequency_roles(
    *,
    value_pattern: str,
    profile_hint: str | None,
    freq_values: list[dict[str, object]],
) -> dict[str, object]:
    field_map = {item["field"]: item for item in freq_values}
    if value_pattern == "uniform":
        mhz = field_map["a"]["mhz"]
        return {
            "likely_tx_mhz": mhz,
            "likely_rx_mhz": mhz,
            "frequency_mapping_hint": "simplex_shared",
        }
    if value_pattern == "a_plus_pair" and profile_hint in {"split_pair_like", "paired_frequency_like"}:
        return {
            "likely_tx_mhz": field_map["a"]["mhz"],
            "likely_rx_mhz": field_map["b"]["mhz"],
            "frequency_mapping_hint": "a_is_tx_b_c_is_rx",
        }
    return {
        "likely_tx_mhz": None,
        "likely_rx_mhz": None,
        "frequency_mapping_hint": None,
    }


def _count_mostly_printable(labels: list[str]) -> int:
    score = 0
    for text in labels:
        if not text:
            continue
        printable = sum(32 <= ord(ch) <= 126 for ch in text)
        if printable / max(len(text), 1) >= 0.85:
            score += 1
    return score


def _text_layout_candidates(
    data: bytes,
    *,
    offset_range: range,
    width_range: range,
    slot_range: range,
    allow_trailer: set[int],
    preferred: set[tuple[int, int]],
) -> tuple[int, int, list[str]] | None:
    candidates: list[tuple[tuple[int, int, int, int], int, int, list[str]]] = []
    for offset in offset_range:
        for slots in slot_range:
            for width in width_range:
                trailing = len(data) - (offset + slots * width)
                if trailing not in allow_trailer:
                    continue
                labels = [
                    _decode_ascii_slot(data, offset + index * width, width)
                    for index in range(slots)
                ]
                printable = _count_mostly_printable(labels)
                nonblank = sum(1 for text in labels if text)
                total_chars = sum(len(text) for text in labels if text)
                preferred_flag = 1 if (slots, width) in preferred else 0
                candidates.append(
                    (
                        (preferred_flag, printable, nonblank, total_chars, -trailing, -offset),
                        offset,
                        width,
                        labels,
                    )
                )
    if not candidates:
        return None
    _, offset, width, labels = max(candidates, key=lambda item: item[0])
    return offset, width, labels


@dataclass(frozen=True)
class StreamRecord:
    sid: int
    header: str
    header_name: str
    raw_size: int


class Astro25Codeplug:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.streams = self._load_streams(self.path)
        if not self.streams:
            raise ValueError(f"No DataStg/Strm_* streams found in {self.path}")
        self.key = self._derive_key(self.streams)
        self.decrypted_streams = {
            sid: self._decrypt_stream(raw) for sid, raw in self.streams.items()
        }
        self.key = self._refine_key_from_anchors()
        self.decrypted_streams = {
            sid: self._decrypt_stream(raw) for sid, raw in self.streams.items()
        }

    @staticmethod
    def _load_streams(path: Path) -> dict[int, bytes]:
        streams: dict[int, bytes] = {}
        with olefile.OleFileIO(str(path)) as ole:
            for i in range(300):
                stream_name = f"DataStg/Strm_{i}"
                try:
                    streams[i] = ole.openstream(stream_name).read()
                except OSError:
                    continue
                except IOError:
                    continue
        return streams

    @staticmethod
    def _derive_key(streams: dict[int, bytes]) -> list[int]:
        max_len = max(len(data) for data in streams.values())
        key: list[int] = []
        for offset in range(max_len - 2):
            raw_pos = offset + 2
            values = [data[raw_pos] for data in streams.values() if raw_pos < len(data)]
            key.append(Counter(values).most_common(1)[0][0] if values else 0)
        return key

    def _decrypt_stream(self, raw: bytes) -> bytes:
        return bytes(
            raw[2 + idx] ^ self.key[idx] if idx < len(self.key) else raw[2 + idx]
            for idx in range(len(raw) - 2)
        )

    def iter_streams(self) -> list[StreamRecord]:
        records = []
        for sid, raw in sorted(self.streams.items()):
            header = raw[:2].hex()
            records.append(
                StreamRecord(
                    sid=sid,
                    header=header,
                    header_name=HEADER_NAMES.get(header, "unknown"),
                    raw_size=len(raw),
                )
            )
        return records

    def stream_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for record in self.iter_streams():
            label = f"{record.header}:{record.header_name}"
            counts[label] = counts.get(label, 0) + 1
        return dict(sorted(counts.items()))

    def classify_variant(self) -> dict[str, object]:
        c5_lengths = sorted(
            {len(self.decrypted_streams[sid]) for sid, raw in self.streams.items() if raw[:2].hex() == "84c5"}
        )
        c7_lengths = sorted(
            {len(self.decrypted_streams[sid]) for sid, raw in self.streams.items() if raw[:2].hex() == "84c7"}
        )
        if c5_lengths in ([27], [29], [27, 29]) and c7_lengths in ([46], [47], [46, 47]):
            family = "legacy_single_zone"
        elif c5_lengths == [284] and c7_lengths == [222, 362]:
            family = "w6slg_multizone_variant"
        elif c5_lengths == [252] and c7_lengths == [222, 362]:
            family = "multizone_compact_labels"
        elif any(length >= 300 for length in c5_lengths):
            family = "extended_labels_or_newer_family"
        else:
            family = "unknown"
        return {
            "family": family,
            "c5_lengths": c5_lengths,
            "c7_lengths": c7_lengths,
            "has_849b": any(raw[:2].hex() == "849b" for raw in self.streams.values()),
        }

    def unknown_header_inventory(self) -> list[dict[str, object]]:
        grouped: dict[str, list[tuple[int, int]]] = {}
        for sid, raw in self.streams.items():
            header = raw[:2].hex()
            if header in KNOWN_HEADERS:
                continue
            grouped.setdefault(header, []).append((sid, len(self.decrypted_streams[sid])))
        rows = []
        for header, items in sorted(grouped.items()):
            rows.append(
                {
                    "header": header,
                    "count": len(items),
                    "sizes": sorted({size for _, size in items}),
                    "sids": [sid for sid, _ in sorted(items)[:8]],
                }
            )
        return rows

    def directory_entries(self) -> list[dict[str, object]]:
        raw = self.decrypted_streams.get(0)
        if raw is None:
            return []
        max_sid = max(self.streams)
        entries: list[dict[str, object]] = []
        for entry_index in range(len(raw) // 10):
            offset = entry_index * 10
            chunk = raw[offset : offset + 10]
            if len(chunk) < 10:
                break
            if entries and not any(chunk):
                break
            record_index_word = struct.unpack_from(">H", chunk, 0)[0]
            marker = struct.unpack_from(">H", chunk, 2)[0]
            crc = struct.unpack_from(">H", chunk, 4)[0]
            sid = struct.unpack_from(">H", chunk, 6)[0]
            extra = struct.unpack_from(">H", chunk, 8)[0]
            if marker not in {0x0080, 0x0081, 0x008D}:
                continue
            if sid > max_sid:
                continue
            if sid == 0 and marker == 0:
                continue
            stream = self.streams.get(sid)
            extra_info = _decode_directory_extra(extra)
            entries.append(
                {
                    "entry": entry_index,
                    "record_index_word": record_index_word,
                    "marker": marker,
                    "crc": crc,
                    "sid": sid,
                    "header": stream[:2].hex() if stream else "????",
                    "header_name": HEADER_NAMES.get(stream[:2].hex(), "missing") if stream else "missing",
                    "extra_raw": extra,
                    "extra": extra_info,
                }
            )
        return entries

    def radio_identity(self) -> dict[str, str | None]:
        result = {"model": None, "codeplug_serial": None, "version": None}
        for sid, raw in self.streams.items():
            header = raw[:2].hex()
            decrypted = self.decrypted_streams[sid]
            if header == "9b3e":
                match = MODEL_RE.search(decrypted)
                if match:
                    result["model"] = match.group(0).decode("ascii", "replace")
            elif header == "9b3c":
                match = SERIAL_RE.search(decrypted)
                if match:
                    result["codeplug_serial"] = match.group(0).decode("ascii", "replace")
            elif header == "8b7d":
                match = VERSION_RE.search(decrypted)
                if match:
                    result["version"] = match.group(0).decode("ascii", "replace").strip()
        return result

    def metadata_candidates(self) -> dict[str, list[str]]:
        candidates = {"radio_identity": [], "codeplug_serial": [], "version": []}
        for sid, raw in self.streams.items():
            header = raw[:2].hex()
            if header not in {"9b3e", "9b3c", "8b7d"}:
                continue
            runs = _extract_printable_ascii_runs(self.decrypted_streams[sid])
            if header == "9b3e":
                candidates["radio_identity"].extend(runs)
            elif header == "9b3c":
                candidates["codeplug_serial"].extend(runs)
            else:
                candidates["version"].extend(runs)
        return candidates

    def text_payload_records(self) -> list[dict[str, object]]:
        excluded_headers = {"9b3e", "9b3c", "8b7d", "84c5", "8b61", "8b63"}
        rows = []
        for sid, raw in sorted(self.streams.items()):
            header = raw[:2].hex()
            if header in excluded_headers:
                continue
            runs = _extract_printable_ascii_runs(self.decrypted_streams[sid])
            if not runs:
                continue
            rows.append(
                {
                    "sid": sid,
                    "header": header,
                    "header_name": HEADER_NAMES.get(header, "unknown"),
                    "length": len(self.decrypted_streams[sid]),
                    "text_runs": runs,
                }
            )
        return rows

    def support_cluster_records(self) -> list[dict[str, object]]:
        rows = []
        for sid, raw in sorted(self.streams.items()):
            header = raw[:2].hex()
            if header not in SUPPORT_CLUSTER_HEADERS:
                continue
            decrypted = self.decrypted_streams[sid]
            words = [
                struct.unpack_from(">H", decrypted, offset)[0]
                for offset in range(0, len(decrypted) - 1, 2)
            ]
            row = {
                "sid": sid,
                "header": header,
                "header_name": HEADER_NAMES.get(header, "unknown"),
                "length": len(decrypted),
                "record_index": words[0] if words else None,
                "payload_length_word": words[1] if len(words) > 1 else None,
                "words": words[:-1] if words else [],
                "crc_or_tail_word": words[-1] if words else None,
                "raw_hex": decrypted.hex(" "),
            }
            if header in {"84f8", "84fb"}:
                table_offset = 10
                if len(decrypted) > 12 and decrypted[10] > 0x20:
                    table_offset = 12
                table_bytes = decrypted[table_offset:-2] if len(decrypted) > table_offset + 2 else b""
                row.update(
                    {
                        "table_offset": table_offset,
                        "table_bytes": list(table_bytes),
                        "table_length": len(table_bytes),
                        "table_kind": (
                            "sequential"
                            if table_bytes == bytes(range(1, len(table_bytes) + 1))
                            else "custom"
                        ),
                    }
                )
            else:
                candidate_sid_refs = []
                fallback_sid_refs = []
                seen_ref_sids: set[int] = set()
                candidate_frequency_words = []
                for word in words[:-1] if words else []:
                    if word in self.streams and word not in {sid}:
                        if word in seen_ref_sids:
                            continue
                        seen_ref_sids.add(word)
                        ref = _format_sid_reference(self, word)
                        ref["ref_group"] = _classify_ref_group(ref["header"])
                        if ref["ref_group"] != "metadata":
                            candidate_sid_refs.append(ref)
                        else:
                            fallback_sid_refs.append(ref)
                    if 3000 <= word <= 7000:
                        candidate_frequency_words.append(
                            {
                                "word": word,
                                "mhz": decode_freq(word),
                            }
                        )
                if not candidate_sid_refs:
                    candidate_sid_refs = fallback_sid_refs
                row.update(
                    {
                        "candidate_sid_refs": candidate_sid_refs[:8],
                        "candidate_frequency_words": candidate_frequency_words[:8],
                    }
                )
            rows.append(row)
        return rows

    def channel_names(self) -> list[dict[str, object]]:
        names = []
        for sid, raw in sorted(self.streams.items()):
            if raw[:2].hex() != "84c5":
                continue
            decrypted = self.decrypted_streams[sid]
            names.append(
                {
                    "sid": sid,
                    "name": _decode_ascii_blob(decrypted[10:]),
                    "record_index": struct.unpack_from(">H", decrypted, 0)[0] if len(decrypted) >= 2 else None,
                    "size": len(decrypted),
                }
            )
        return names

    def zone_companion_records(self) -> list[dict[str, object]]:
        variant = self.classify_variant()["family"]
        rows = []
        for sid, raw in sorted(self.streams.items()):
            header = raw[:2].hex()
            if header not in {"84c4", "84c6"}:
                continue
            decrypted = self.decrypted_streams[sid]
            words = [
                struct.unpack_from(">H", decrypted, offset)[0]
                for offset in range(0, len(decrypted) - 1, 2)
            ]
            if not words:
                continue
            record_index = words[0]
            row = {
                "sid": sid,
                "header": header,
                "header_name": HEADER_NAMES.get(header, "unknown"),
                "length": len(decrypted),
                "record_index": record_index,
                "word_values": words[:-1],
                "crc_or_tail_word": words[-1],
            }
            if header == "84c4":
                row.update(
                    {
                        "field_1": words[1] if len(words) > 1 else None,
                        "field_2": words[2] if len(words) > 2 else None,
                        "label_width": words[3] if len(words) > 3 and 8 <= words[3] <= 24 else None,
                        "field_4": words[4] if len(words) > 4 else None,
                        "record_length_word": words[5] if len(words) > 5 else None,
                        "flags_word": words[6] if len(words) > 6 else None,
                        "c5_record_index": words[7] if len(words) > 7 and words[7] < 512 else None,
                    }
                )
            else:
                visible_slot_count = None
                if (
                    variant in {"w6slg_multizone_variant", "multizone_compact_labels"}
                    and len(words) > 1
                    and 1 <= words[1] <= 63
                    and words[1] % 2 == 1
                ):
                    visible_slot_count = (words[1] + 1) // 2
                c7_base_record_index = None
                if len(words) > 7 and words[7] < 512:
                    if words[3] == 35 or variant in {"legacy_single_zone", "w6slg_multizone_variant", "multizone_compact_labels"}:
                        c7_base_record_index = words[7]
                row.update(
                    {
                        "field_1": words[1] if len(words) > 1 else None,
                        "field_2": words[2] if len(words) > 2 else None,
                        "c7_entry_width": words[3] if len(words) > 3 else None,
                        "field_4": words[4] if len(words) > 4 else None,
                        "entry_count_hint": words[5] if len(words) > 5 else None,
                        "flags_word": words[6] if len(words) > 6 else None,
                        "c7_base_record_index": c7_base_record_index,
                        "visible_slot_count": visible_slot_count,
                    }
                )
                if c7_base_record_index is not None:
                    row["c7_pair_record_indexes"] = [c7_base_record_index, c7_base_record_index + 1]
            rows.append(row)
        return rows

    def zone_control_records(self) -> list[dict[str, object]]:
        rows = []
        for sid, raw in sorted(self.streams.items()):
            header = raw[:2].hex()
            if header not in {"84ca", "84cb", "849b"}:
                continue
            decrypted = self.decrypted_streams[sid]
            words = [
                struct.unpack_from(">H", decrypted, offset)[0]
                for offset in range(0, len(decrypted) - 1, 2)
            ]
            if not words:
                continue
            row = {
                "sid": sid,
                "header": header,
                "header_name": HEADER_NAMES.get(header, "unknown"),
                "length": len(decrypted),
                "record_index": words[0],
                "payload_length_word": words[1] if len(words) > 1 else None,
                "schema_word_a": words[2] if len(words) > 2 else None,
                "schema_word_b": words[3] if len(words) > 3 else None,
                "span_or_count_hint": words[4] if len(words) > 4 else None,
                "words": words[:-1],
                "crc_or_tail_word": words[-1],
            }
            if header == "84ca":
                row.update(
                    {
                        "routing_words": words[5:9],
                        "tail_signature": words[-5:-1] if len(words) >= 5 else [],
                    }
                )
            elif header == "84cb":
                row.update(
                    {
                        "routing_words": words[5:9],
                        "control_words": words[9:13],
                        "tail_signature": words[-3:-1] if len(words) >= 3 else [],
                    }
                )
            else:
                row.update(
                    {
                        "profile_word": words[2] if len(words) > 2 else None,
                        "profile_index_hint": words[3] if len(words) > 3 else None,
                        "embedded_cb_signature": words[9:16],
                        "embedded_ca_signature": words[24:31] if len(words) > 31 else [],
                    }
                )
            rows.append(row)
        return rows

    def zone_label_tables(self) -> list[dict[str, object]]:
        c4_by_record_index = {
            row["record_index"]: row
            for row in self.zone_companion_records()
            if row["header"] == "84c4"
        }
        c6_by_record_index = {
            row["record_index"]: row
            for row in self.zone_companion_records()
            if row["header"] == "84c6"
        }
        tables = []
        for sid, raw in sorted(self.streams.items()):
            if raw[:2].hex() != "84c5":
                continue
            decrypted = self.decrypted_streams[sid]
            record_index = struct.unpack_from(">H", decrypted, 0)[0] if len(decrypted) >= 2 else 0
            zone_label = None
            label_base_offset = None
            slot_width = None
            slot_count = None
            layout_source = "heuristic"
            c4_companion = c4_by_record_index.get(record_index)
            c6_companion = c6_by_record_index.get(record_index)
            if c4_companion and c6_companion:
                slot_width = c4_companion.get("label_width")
                slot_count = c6_companion.get("visible_slot_count")
                if slot_width and slot_count:
                    compact_sizes = {10 + slot_width * slot_count, 12 + slot_width * slot_count}
                    headered_sizes = {27 + slot_width * slot_count, 29 + slot_width * slot_count}
                    if len(decrypted) in compact_sizes:
                        label_base_offset = 10
                        layout_source = "84c4/84c6"
                    elif len(decrypted) in headered_sizes:
                        label_base_offset = 27
                        zone_label = _decode_ascii_blob(decrypted[10:27]) or None
                        layout_source = "84c4/84c6"

            labels = []
            if label_base_offset is not None and slot_width and slot_count:
                for slot_index in range(slot_count):
                    slot_offset = label_base_offset + slot_index * slot_width
                    slot_bytes = decrypted[slot_offset : slot_offset + slot_width]
                    labels.append(
                        {
                            "slot": slot_index,
                            "offset": slot_offset,
                            "text": _decode_ascii_blob(slot_bytes),
                            "raw_hex": slot_bytes.hex(),
                            "non_ascii_bytes": _slot_non_ascii_bytes(decrypted, slot_offset, slot_width),
                        }
                    )
            else:
                best = _text_layout_candidates(
                    decrypted,
                    offset_range=range(10, 28),
                    width_range=range(8, 25),
                    slot_range=range(1, 33),
                    allow_trailer={0, 2},
                    preferred={(1, 15), (1, 17), (15, 15), (15, 17), (16, 15), (16, 17)},
                )
                if best:
                    label_base_offset, slot_width, texts = best
                    slot_count = len(texts)
                    if slot_count == 1:
                        zone_label = texts[0] or None
                    for slot_index in range(slot_count):
                        slot_offset = label_base_offset + slot_index * slot_width
                        slot_bytes = decrypted[slot_offset : slot_offset + slot_width]
                        labels.append(
                            {
                                "slot": slot_index,
                                "offset": slot_offset,
                                "text": _decode_ascii_blob(slot_bytes),
                                "raw_hex": slot_bytes.hex(),
                                "non_ascii_bytes": _slot_non_ascii_bytes(decrypted, slot_offset, slot_width),
                            }
                        )
                elif len(decrypted) > 10:
                    zone_label = _decode_ascii_slot(decrypted, 10, min(17, max(0, len(decrypted) - 12)))
                    if zone_label:
                        labels.append(
                            {
                                "slot": 0,
                                "offset": 10,
                                "text": zone_label,
                                "raw_hex": decrypted[10 : min(len(decrypted), 27)].hex(),
                                "non_ascii_bytes": _slot_non_ascii_bytes(
                                    decrypted,
                                    10,
                                    min(17, max(0, len(decrypted) - 12)),
                                ),
                            }
                        )
            tables.append(
                {
                    "sid": sid,
                    "record_index": record_index,
                    "length": len(decrypted),
                    "zone_label": zone_label,
                    "label_base_offset": label_base_offset,
                    "layout_source": layout_source,
                    "slot_width": slot_width,
                    "slot_count": slot_count,
                    "labels": labels,
                }
            )
        return tables

    def global_text_tables(self) -> list[dict[str, object]]:
        rows = []
        for sid, raw in sorted(self.streams.items()):
            header = raw[:2].hex()
            if header not in {"8b61", "8b63"}:
                continue
            decrypted = self.decrypted_streams[sid]
            labels = []
            offset = None
            width = None
            slot_count = None
            if len(decrypted) == 286:
                offset = 12
                width = 17
                slot_count = 16
                texts = [
                    _decode_ascii_slot(decrypted, offset + index * width, width)
                    for index in range(slot_count)
                ]
                for index, text in enumerate(texts):
                    labels.append(
                        {
                            "slot": index,
                            "offset": offset + index * width,
                            "text": text,
                            "raw_hex": decrypted[offset + index * width : offset + (index + 1) * width].hex(),
                            "non_ascii_bytes": _slot_non_ascii_bytes(
                                decrypted,
                                offset + index * width,
                                width,
                            ),
                        }
                    )
            else:
                best = _text_layout_candidates(
                    decrypted,
                    offset_range=range(10, 17),
                    width_range=range(13, 19),
                    slot_range=range(1, 33),
                    allow_trailer={0, 2, 4},
                    preferred={(1, 17), (14, 17), (16, 17)},
                )
                if best:
                    offset, width, texts = best
                    slot_count = len(texts)
                    for index, text in enumerate(texts):
                        labels.append(
                            {
                                "slot": index,
                                "offset": offset + index * width,
                                "text": text,
                                "raw_hex": decrypted[offset + index * width : offset + (index + 1) * width].hex(),
                                "non_ascii_bytes": _slot_non_ascii_bytes(
                                    decrypted,
                                    offset + index * width,
                                    width,
                                ),
                            }
                        )
            rows.append(
                {
                    "sid": sid,
                    "header": header,
                    "header_name": HEADER_NAMES.get(header, "unknown"),
                    "record_index": struct.unpack_from(">H", decrypted, 0)[0] if len(decrypted) >= 2 else 0,
                    "length": len(decrypted),
                    "slot_width": width,
                    "slot_count": slot_count,
                    "labels": labels,
                }
            )
        return rows

    def tone_blocks(self) -> list[dict[str, object]]:
        tones = []
        for sid, raw in sorted(self.streams.items()):
            if raw[:2].hex() != "848e":
                continue
            decrypted = self.decrypted_streams[sid]
            if len(decrypted) < 19:
                continue
            rx_index = decrypted[11]
            tx_index = decrypted[13]
            tones.append(
                {
                    "sid": sid,
                    "rx_index": rx_index,
                    "tx_index": tx_index,
                    "rx_hz": CTCSS[rx_index] if rx_index < len(CTCSS) else None,
                    "tx_hz": CTCSS[tx_index] if tx_index < len(CTCSS) else None,
                    "config_counter": decrypted[9],
                }
            )
        return tones

    def personalities(self) -> list[dict[str, object]]:
        items = []
        power_names = {0xC0: "high", 0x80: "medium", 0x00: "low"}
        for sid, raw in sorted(self.streams.items()):
            if raw[:2].hex() != "84c1":
                continue
            decrypted = self.decrypted_streams[sid]
            if len(decrypted) < 17:
                continue
            rx_value = struct.unpack_from(">H", decrypted, 5)[0]
            rx_mhz = decode_freq(rx_value)
            band_variant = decrypted[10]
            band = _guess_band_name(decrypted[9], rx_mhz)
            items.append(
                {
                    "sid": sid,
                    "record_index": struct.unpack_from(">H", decrypted, 0)[0],
                    "ctcss_enabled": bool(decrypted[4] & 0x04),
                    "rx_mhz": rx_mhz,
                    "tx_mhz": _guess_tx_frequency(rx_mhz, band, band_variant),
                    "band": band,
                    "band_variant": band_variant,
                    "tx_power": power_names.get(decrypted[11], f"0x{decrypted[11]:02x}"),
                    "channel_mode": decrypted[14],
                    "squelch": decrypted[15],
                    "mode_flags": decrypted[16],
                }
            )
        return items

    def personality_variants(self) -> list[dict[str, object]]:
        grouped: dict[bytes, list[dict[str, object]]] = {}
        for row in self.personalities():
            decrypted = self.decrypted_streams[row["sid"]]
            signature = decrypted[2:7] + decrypted[9:79]
            grouped.setdefault(signature, []).append(row)
        variants = []
        for variant_index, items in enumerate(
            sorted(grouped.values(), key=lambda rows: (-len(rows), rows[0]["sid"])),
            1,
        ):
            exemplar = items[0]
            variants.append(
                {
                    "variant_index": variant_index,
                    "count": len(items),
                    "sids": [row["sid"] for row in items],
                    "record_indexes": [row["record_index"] for row in items],
                    "rx_mhz": exemplar["rx_mhz"],
                    "tx_mhz": exemplar["tx_mhz"],
                    "band": exemplar["band"],
                    "band_variant": exemplar["band_variant"],
                    "tx_power": exemplar["tx_power"],
                    "ctcss_enabled": exemplar["ctcss_enabled"],
                    "channel_mode": exemplar["channel_mode"],
                    "squelch": exemplar["squelch"],
                    "mode_flags": exemplar["mode_flags"],
                }
            )
        return variants

    def channel_configs(self) -> list[dict[str, object]]:
        rows = []
        for sid, raw in sorted(self.streams.items()):
            header = raw[:2].hex()
            if header not in {"84cd", "84cf", "84f0", "8495", "8489"}:
                continue
            decrypted = self.decrypted_streams[sid]
            if len(decrypted) < 12:
                continue
            entry = {
                "sid": sid,
                "header": header,
                "record_index": struct.unpack_from(">H", decrypted, 0)[0],
                "payload_length": struct.unpack_from(">H", decrypted, 2)[0] if len(decrypted) >= 4 else None,
                "flags": struct.unpack_from(">H", decrypted, 4)[0] if len(decrypted) >= 6 else None,
                "member_count": struct.unpack_from(">H", decrypted, 6)[0] if len(decrypted) >= 8 else None,
                "ref_a_sid": struct.unpack_from(">H", decrypted, 8)[0] if len(decrypted) >= 10 else None,
                "ref_b_sid": None,
                "freq_a_mhz": None,
                "freq_b_mhz": None,
                "pad_word": None,
                "variant_word": None,
                "extended_hex": "",
                "crc_or_tail_word": struct.unpack_from(">H", decrypted, len(decrypted) - 2)[0]
                if len(decrypted) >= 2
                else None,
            }
            if header == "84cf":
                entry["variant_word"] = struct.unpack_from(">H", decrypted, 10)[0] if len(decrypted) >= 12 else None
                entry["freq_a_mhz"] = (
                    decode_freq(struct.unpack_from(">H", decrypted, 12)[0]) if len(decrypted) >= 14 else None
                )
                entry["extended_hex"] = decrypted[14:-2].hex(" ") if len(decrypted) > 16 else ""
            else:
                entry["ref_b_sid"] = struct.unpack_from(">H", decrypted, 10)[0] if len(decrypted) >= 12 else None
                entry["freq_a_mhz"] = (
                    decode_freq(struct.unpack_from(">H", decrypted, 12)[0]) if len(decrypted) >= 14 else None
                )
                entry["pad_word"] = struct.unpack_from(">H", decrypted, 14)[0] if len(decrypted) >= 16 else None
                entry["freq_b_mhz"] = (
                    decode_freq(struct.unpack_from(">H", decrypted, 16)[0]) if len(decrypted) >= 18 else None
                )
                entry["extended_hex"] = decrypted[18:-2].hex(" ") if len(decrypted) > 20 else ""
            rows.append(entry)
        return rows

    def scan_list_members(self) -> list[dict[str, object]]:
        rows = []
        for sid, raw in sorted(self.streams.items()):
            if raw[:2].hex() != "84f7":
                continue
            decrypted = self.decrypted_streams[sid]
            if len(decrypted) < 16:
                continue
            rx_word = struct.unpack_from(">H", decrypted, 6)[0]
            tx_word = struct.unpack_from(">H", decrypted, 10)[0]
            rows.append(
                {
                    "sid": sid,
                    "record_index": struct.unpack_from(">H", decrypted, 0)[0],
                    "state_word": struct.unpack_from(">H", decrypted, 2)[0],
                    "active_code": decrypted[4],
                    "flags": decrypted[9],
                    "rx_word": rx_word,
                    "rx_mhz": decode_freq(rx_word) if 3000 <= rx_word <= 7000 else None,
                    "tx_word": tx_word,
                    "tx_mhz": decode_freq(tx_word) if 3000 <= tx_word <= 7000 else None,
                    "tail_word": struct.unpack_from(">H", decrypted, 14)[0],
                }
            )
        return rows

    def channel_group_refs(self) -> list[dict[str, object]]:
        groups = []
        for sid, raw in sorted(self.streams.items()):
            if raw[:2].hex() != "8b21":
                continue
            decrypted = self.decrypted_streams[sid]
            pairs = []
            repeated_value_offsets: set[int] = set()
            for offset in range(8, len(decrypted) - 1, 2):
                tag = decrypted[offset]
                value = decrypted[offset + 1]
                pairs.append(
                    {
                        "offset": offset,
                        "tag": tag,
                        "tag_hex": f"0x{tag:02x}",
                        "value": value,
                    }
                )
            run_start = 0
            while run_start < len(pairs):
                run_end = run_start + 1
                while run_end < len(pairs) and pairs[run_end]["value"] == pairs[run_start]["value"]:
                    run_end += 1
                if run_end - run_start >= 4:
                    repeated_value_offsets.update(pair["offset"] for pair in pairs[run_start:run_end])
                run_start = run_end

            tagged_refs = []
            for pair in pairs:
                value = pair["value"]
                kind = "value"
                ref = None
                ref_group = None
                if pair["offset"] in repeated_value_offsets:
                    kind = "value_run"
                elif value in self.streams:
                    ref = _format_sid_reference(self, value)
                    ref_group = _classify_ref_group(ref["header"])
                    kind = "self_ref" if value == sid else "sid_ref"
                pair["kind"] = kind
                if ref:
                    pair.update(ref)
                    pair["ref_group"] = ref_group
                    tagged_refs.append(pair)
            groups.append(
                {
                    "sid": sid,
                    "length": len(decrypted),
                    "record_index": struct.unpack_from(">H", decrypted, 0)[0],
                    "payload_length": struct.unpack_from(">H", decrypted, 2)[0] if len(decrypted) >= 4 else None,
                    "pairs": pairs,
                    "tagged_refs": tagged_refs,
                }
            )
        return groups

    def _parse_84c7_layout(self, decrypted: bytes) -> tuple[int, int, int]:
        if len(decrypted) >= 11 and (len(decrypted) - 11) % 35 == 0:
            return 11, 0, (len(decrypted) - 11) // 35
        if len(decrypted) >= 12 and (len(decrypted) - 12) % 35 == 0:
            return 12, 0, (len(decrypted) - 12) // 35
        return len(decrypted), 0, 0

    def extended_c7_blocks(self) -> list[dict[str, object]]:
        rows = []
        for sid, raw in sorted(self.streams.items()):
            if raw[:2].hex() != "84c7":
                continue
            decrypted = self.decrypted_streams[sid]
            header_len, trailer_len, block_count = self._parse_84c7_layout(decrypted)
            header_words = [
                struct.unpack_from(">H", decrypted, pos)[0]
                for pos in range(0, header_len - (header_len % 2), 2)
            ]
            header_length_word = header_words[1] if len(header_words) > 1 else None
            header_flags_word = header_words[2] if len(header_words) > 2 else None
            header_link_word = header_words[3] if len(header_words) > 3 else None
            header_span_word = header_words[4] if len(header_words) > 4 else None
            header_tail_placeholder_word = header_words[-1] if header_words else None
            blocks = []
            body = decrypted[header_len : len(decrypted) - trailer_len if trailer_len else len(decrypted)]
            for index in range(block_count):
                chunk = body[index * 35 : (index + 1) * 35]
                words = [struct.unpack_from(">H", chunk, pos)[0] for pos in range(0, len(chunk) - 1, 2)]
                entry_code = struct.unpack_from(">H", chunk, 0)[0]
                entry_index = chunk[1] if chunk and chunk[0] == 0 else None
                selector = struct.unpack_from(">H", chunk, 2)[0]
                selector_freq = decode_freq(selector) if 3000 <= selector <= 7000 else None
                entry_freq = decode_freq(entry_code) if 3000 <= entry_code <= 7000 else None
                block_class = "standard" if any(chunk[2:10]) else "auxiliary"
                ctcss_candidate_hz = (
                    CTCSS[entry_index]
                    if block_class == "standard" and entry_index is not None and 1 <= entry_index < len(CTCSS)
                    else None
                )
                value_a = int.from_bytes(chunk[10:14], "big")
                value_b = int.from_bytes(chunk[14:18], "big")
                value_c = int.from_bytes(chunk[18:22], "big")
                freq_values = [
                    {"field": "a", **_decode_u32_freq_candidate(value_a)},
                    {"field": "b", **_decode_u32_freq_candidate(value_b)},
                    {"field": "c", **_decode_u32_freq_candidate(value_c)},
                ]
                if value_a == value_b == value_c:
                    value_pattern = "uniform"
                elif value_b == value_c and value_a != value_b:
                    value_pattern = "a_plus_pair"
                else:
                    value_pattern = "mixed"
                flag_bytes_hex = chunk[22:25].hex(" ")
                profile_hint = _infer_c7_profile_hint(
                    block_class=block_class,
                    flags_hex=flag_bytes_hex,
                    freq_values=freq_values,
                )
                role_info = _infer_c7_frequency_roles(
                    value_pattern=value_pattern,
                    profile_hint=profile_hint,
                    freq_values=freq_values,
                )
                sid_refs = [
                    _format_sid_reference(self, word)
                    for word in words
                    if word in self.streams and word not in {0, sid}
                ]
                entry_ref = None
                entry_kind = "auxiliary"
                if block_class == "standard" and entry_index is not None:
                    entry_kind = "entry_index"
                elif entry_code in self.streams and entry_code not in {0, sid}:
                    entry_ref = _format_sid_reference(self, entry_code)
                    entry_kind = "stream_ref"
                elif block_class == "standard" and entry_freq is not None:
                    entry_kind = "frequency"
                blocks.append(
                    {
                        "index": index,
                        "block_class": block_class,
                        "hex": chunk.hex(" "),
                        "entry_code": entry_code,
                        "entry_index": entry_index,
                        "entry_kind": entry_kind,
                        "entry_frequency_mhz": entry_freq,
                        "ctcss_candidate_hz": ctcss_candidate_hz,
                        "entry_ref": entry_ref,
                        "selector": selector,
                        "selector_frequency_mhz": selector_freq,
                        "prefix_hex": chunk[:10].hex(" "),
                        "value_a_u32": value_a,
                        "value_a_hex": f"0x{value_a:08x}",
                        "value_b_u32": value_b,
                        "value_b_hex": f"0x{value_b:08x}",
                        "value_c_u32": value_c,
                        "value_c_hex": f"0x{value_c:08x}",
                        "frequency_values": freq_values,
                        "value_pattern": value_pattern,
                        "flag_bytes_hex": flag_bytes_hex,
                        "profile_hint": profile_hint,
                        "likely_tx_mhz": role_info["likely_tx_mhz"],
                        "likely_rx_mhz": role_info["likely_rx_mhz"],
                        "frequency_mapping_hint": role_info["frequency_mapping_hint"],
                        "tail_hex": chunk[25:].hex(" "),
                        "trailing_byte": chunk[-1],
                        "words": words,
                        "sid_refs": sid_refs,
                    }
                )
            rows.append(
                {
                    "sid": sid,
                    "length": len(decrypted),
                    "record_index": struct.unpack_from(">H", decrypted, 0)[0],
                    "payload_length": struct.unpack_from(">H", decrypted, 2)[0] if len(decrypted) >= 4 else None,
                    "header_words": header_words,
                    "header_words_hex": [f"0x{word:04x}" for word in header_words],
                    "header_length_word": header_length_word,
                    "header_length_delta_to_stream": (
                        len(decrypted) - header_length_word if header_length_word is not None else None
                    ),
                    "header_flags_word": header_flags_word,
                    "header_flags_word_hex": (
                        f"0x{header_flags_word:04x}" if header_flags_word is not None else None
                    ),
                    "header_link_word": header_link_word,
                    "header_link_word_hex": (
                        f"0x{header_link_word:04x}" if header_link_word is not None else None
                    ),
                    "header_span_word": header_span_word,
                    "header_span_word_hex": (
                        f"0x{header_span_word:04x}" if header_span_word is not None else None
                    ),
                    "header_tail_placeholder_word": header_tail_placeholder_word,
                    "header_tail_placeholder_word_hex": (
                        f"0x{header_tail_placeholder_word:04x}"
                        if header_tail_placeholder_word is not None
                        else None
                    ),
                    "header_length": header_len,
                    "trailer_length": trailer_len,
                    "block_count": block_count,
                    "standard_block_count": sum(1 for block in blocks if block["block_class"] == "standard"),
                    "auxiliary_block_count": sum(1 for block in blocks if block["block_class"] == "auxiliary"),
                    "header_hex": decrypted[:header_len].hex(" "),
                    "trailer_hex": decrypted[-trailer_len:].hex(" ") if trailer_len else "",
                    "blocks": blocks,
                }
            )
        return rows

    def w6slg_multizone_c7_anchor_bytes(self) -> list[dict[str, object]]:
        if self.classify_variant()["family"] != "w6slg_multizone_variant":
            return []

        c7_by_record_index = {
            row["record_index"]: row
            for row in self.extended_c7_blocks()
        }
        c6_by_record_index = {
            row["record_index"]: row
            for row in self.zone_companion_records()
            if row["header"] == "84c6"
        }
        rows = []
        for table in self.zone_label_tables():
            c6_companion = c6_by_record_index.get(table["record_index"])
            if c6_companion is None:
                continue
            base_record_index = c6_companion.get("c7_base_record_index")
            if base_record_index is None:
                continue
            long_row = c7_by_record_index.get(base_record_index)
            if long_row is None or long_row["length"] != 362:
                continue
            standard_blocks = [block for block in long_row["blocks"] if block["block_class"] == "standard"]
            if len(standard_blocks) < 8:
                continue
            profile_block = next((block for block in standard_blocks if block["index"] == 7), standard_blocks[-1])
            profile_bytes = bytes.fromhex(profile_block["hex"])
            prefix_bytes = profile_bytes[2:10]
            flag_bytes = profile_bytes[22:25]
            candidate_tails = [
                bytes.fromhex(block["tail_hex"])
                for block in standard_blocks
                if block["flag_bytes_hex"] == profile_block["flag_bytes_hex"] and block["tail_hex"] and any(bytes.fromhex(block["tail_hex"]))
            ]
            full_tail = Counter(candidate_tails).most_common(1)[0][0] if candidate_tails else b""
            base_entry_index = standard_blocks[0].get("entry_index")
            if base_entry_index is None:
                continue

            sid = long_row["sid"]
            decrypted = self.decrypted_streams[sid]

            if len(full_tail) == 10:
                block7_start = 12 + 7 * 35
                for rel, expected_byte in enumerate(full_tail, start=block7_start + 25):
                    if rel >= len(decrypted):
                        break
                    rows.append(
                        {
                            "sid": sid,
                            "header": "84c7",
                            "offset": rel,
                            "expected_byte": expected_byte,
                            "current_byte": decrypted[rel],
                            "source": "w6slg_c7_nonfinal_tail",
                            "context": f"record={long_row['record_index']} block=7",
                        }
                    )

            for block_index in (8, 9):
                label_index = block_index - 1
                if label_index >= len(table["labels"]):
                    continue
                label_text = table["labels"][label_index]["text"]
                label_frequency_mhz = _extract_label_frequency_mhz(label_text)
                if label_frequency_mhz is None:
                    continue

                expected_entry = (base_entry_index + block_index).to_bytes(2, "big")
                expected_value = _encode_u32_freq_value(label_frequency_mhz).to_bytes(4, "big") * 3
                expected_prefix = expected_entry + prefix_bytes + expected_value + flag_bytes
                block_start = 12 + block_index * 35
                for rel, expected_byte in enumerate(expected_prefix, start=block_start):
                    if rel >= len(decrypted):
                        break
                    rows.append(
                        {
                            "sid": sid,
                            "header": "84c7",
                            "offset": rel,
                            "expected_byte": expected_byte,
                            "current_byte": decrypted[rel],
                            "source": "w6slg_c7_tail_entry",
                            "context": f"record={long_row['record_index']} block={block_index} label={label_text}",
                        }
                    )

                if len(full_tail) == 10:
                    expected_tail = full_tail if block_index == 8 else full_tail[:8]
                    for rel, expected_byte in enumerate(expected_tail, start=block_start + 25):
                        if rel >= len(decrypted):
                            break
                        rows.append(
                            {
                                "sid": sid,
                                "header": "84c7",
                                "offset": rel,
                                "expected_byte": expected_byte,
                                "current_byte": decrypted[rel],
                                "source": "w6slg_c7_tail_shape",
                                "context": f"record={long_row['record_index']} block={block_index}",
                            }
                        )
        return rows

    def _key_recovery_candidates(self) -> list[dict[str, object]]:
        hints_by_offset: dict[tuple[int, int], dict[str, object]] = {}

        def add_hint(
            *,
            offset: int,
            sid: int,
            header: str,
            expected_byte: int,
            current_byte: int,
            source: str,
            context: str,
        ) -> None:
            raw = self.streams[sid]
            if 2 + offset >= len(raw):
                return
            suggested_key = raw[2 + offset] ^ expected_byte
            row = hints_by_offset.setdefault(
                (offset, suggested_key),
                {
                    "offset": offset,
                    "current_key": self.key[offset] if offset < len(self.key) else None,
                    "suggested_key": suggested_key,
                    "support": 0,
                    "sources": [],
                },
            )
            row["support"] += 1
            row["sources"].append(
                {
                    "sid": sid,
                    "header": header,
                    "current_byte": current_byte,
                    "expected_byte": expected_byte,
                    "source": source,
                    "context": context,
                }
            )

        for table in self.global_text_tables():
            decrypted = self.decrypted_streams[table["sid"]]
            fixed_prefix = None
            if (
                table["slot_width"] == 17
                and table["slot_count"] == 16
                and table["length"] == 286
            ):
                if table["header"] == "8b61":
                    fixed_prefix = "MESSAGE"
                elif table["header"] == "8b63":
                    fixed_prefix = "STATUS"
            if fixed_prefix is not None:
                for item in table["labels"]:
                    expected_text = f"{fixed_prefix} {item['slot'] + 1}"
                    encoded = expected_text.encode("ascii")
                    for rel, expected_byte in enumerate(encoded):
                        absolute_offset = item["offset"] + rel
                        if absolute_offset >= len(decrypted):
                            continue
                        current_byte = decrypted[absolute_offset]
                        if current_byte == expected_byte:
                            continue
                        add_hint(
                            offset=absolute_offset,
                            sid=table["sid"],
                            header=table["header"],
                            expected_byte=expected_byte,
                            current_byte=current_byte,
                            source="global_text_fixed_slot",
                            context=expected_text,
                        )
                    for rel in range(len(encoded), table["slot_width"]):
                        absolute_offset = item["offset"] + rel
                        if absolute_offset >= len(decrypted):
                            continue
                        current_byte = decrypted[absolute_offset]
                        if current_byte == 0:
                            continue
                        add_hint(
                            offset=absolute_offset,
                            sid=table["sid"],
                            header=table["header"],
                            expected_byte=0,
                            current_byte=current_byte,
                            source="global_text_fixed_padding",
                            context=expected_text,
                        )
                continue

            clean = []
            for item in table["labels"]:
                text = item["text"]
                if not text:
                    continue
                match = NUMBERED_TEXT_RE.fullmatch(text)
                if not match:
                    continue
                clean.append((item["slot"], match.group(1), int(match.group(2))))
            if len(clean) < 3:
                continue
            prefixes = {prefix for _, prefix, _ in clean}
            if len(prefixes) != 1:
                continue
            prefix = next(iter(prefixes))
            delta_counts = Counter(number - slot for slot, _, number in clean)
            delta, support = delta_counts.most_common(1)[0]
            if support < 3:
                continue
            anchor_slots = sorted(slot for slot, _, number in clean if number - slot == delta)
            if len(anchor_slots) < 3:
                continue
            anchor_start = anchor_slots[0]
            for item in table["labels"]:
                if item["slot"] < anchor_start:
                    continue
                expected_text = f"{prefix} {item['slot'] + delta}"
                for rel, expected_byte in enumerate(expected_text.encode("ascii")):
                    absolute_offset = item["offset"] + rel
                    if absolute_offset >= len(decrypted):
                        continue
                    current_byte = decrypted[absolute_offset]
                    if current_byte == expected_byte:
                        continue
                    add_hint(
                        offset=absolute_offset,
                        sid=table["sid"],
                        header=table["header"],
                        expected_byte=expected_byte,
                        current_byte=current_byte,
                        source="global_text_sequence",
                        context=expected_text,
                    )

        for table in self.zone_label_tables():
            for item in table["labels"]:
                text = item["text"] or ""
                if len(text) < 7:
                    continue
                absolute_offset = item["offset"] + 3
                if absolute_offset >= len(self.decrypted_streams[table["sid"]]):
                    continue
                digit_positions = [0, 1, 2, 4, 5, 6]
                if (
                    len(text) >= 7
                    and all(index < len(text) and text[index].isdigit() for index in digit_positions)
                    and text[3] != "."
                ):
                    add_hint(
                        offset=absolute_offset,
                        sid=table["sid"],
                        header="84c5",
                        expected_byte=ord("."),
                        current_byte=self.decrypted_streams[table["sid"]][absolute_offset],
                        source="frequency_label_dot",
                        context=text,
                    )
                if text.endswith("P25") and " P25" not in text and len(text) >= 11:
                    absolute_offset = item["offset"] + 7
                    add_hint(
                        offset=absolute_offset,
                        sid=table["sid"],
                        header="84c5",
                        expected_byte=ord(" "),
                        current_byte=self.decrypted_streams[table["sid"]][absolute_offset],
                        source="frequency_label_suffix",
                        context=text,
                    )

        for entry in self.directory_entries():
            sid = entry["sid"]
            if sid == 0 or sid not in self.decrypted_streams:
                continue
            decrypted = self.decrypted_streams[sid]
            if len(decrypted) < 2:
                continue
            expected_tail = entry["crc"].to_bytes(2, "big")
            for rel, expected_byte in enumerate(expected_tail, start=len(decrypted) - 2):
                current_byte = decrypted[rel]
                if current_byte == expected_byte:
                    continue
                add_hint(
                    offset=rel,
                    sid=sid,
                    header=self.streams[sid][:2].hex(),
                    expected_byte=expected_byte,
                    current_byte=current_byte,
                    source="directory_crc_tail",
                    context=f"sid={sid} crc=0x{entry['crc']:04x}",
                )

        for item in self.w6slg_multizone_c7_anchor_bytes():
            add_hint(
                offset=item["offset"],
                sid=item["sid"],
                header=item["header"],
                expected_byte=item["expected_byte"],
                current_byte=item["current_byte"],
                source=item["source"],
                context=item["context"],
            )

        rows = []
        for _, row in sorted(
            hints_by_offset.items(),
            key=lambda item: (-item[1]["support"], item[1]["offset"], item[1]["suggested_key"]),
        ):
            row["suggested_key_hex"] = f"0x{row['suggested_key']:02x}"
            row["current_key_hex"] = (
                f"0x{row['current_key']:02x}" if row["current_key"] is not None else None
            )
            rows.append(row)
        return rows

    def _refine_key_from_anchors(self) -> list[int]:
        refined = self.key[:]
        for row in self._key_recovery_candidates():
            if row["support"] >= 2:
                refined[row["offset"]] = row["suggested_key"]
        return refined

    def _matching_integrity_records(self) -> list[dict[str, object]]:
        directory_by_sid = {row["sid"]: row for row in self.directory_entries()}
        rows = []
        for sid, raw in sorted(self.streams.items()):
            if sid not in directory_by_sid:
                continue
            decrypted = self.decrypted_streams[sid]
            if len(decrypted) < 2:
                continue
            stream_tail = int.from_bytes(decrypted[-2:], "big")
            if directory_by_sid[sid]["crc"] != stream_tail:
                continue
            rows.append(
                {
                    "sid": sid,
                    "header": raw[:2].hex(),
                    "length": len(decrypted),
                    "raw": raw,
                    "decrypted": decrypted,
                    "stream_tail": stream_tail,
                }
            )
        return rows

    def integrity_ccitt_profile(self) -> list[dict[str, object]]:
        grouped: dict[int, list[dict[str, object]]] = {}
        for row in self._matching_integrity_records():
            crc_zero = _crc16_zero_poly(
                row["decrypted"][:-2],
                poly=0x1021,
                refin=False,
                refout=False,
            )
            grouped.setdefault(row["length"], []).append(
                {
                    "sid": row["sid"],
                    "header": row["header"],
                    "tail": row["stream_tail"],
                    "tail_hex": f"0x{row['stream_tail']:04x}",
                    "crc_zero": crc_zero,
                    "crc_zero_hex": f"0x{crc_zero:04x}",
                    "length_constant": row["stream_tail"] ^ crc_zero,
                    "length_constant_hex": f"0x{(row['stream_tail'] ^ crc_zero):04x}",
                }
            )

        rows = []
        for length, items in sorted(grouped.items()):
            constants = sorted({item["length_constant"] for item in items})
            rows.append(
                {
                    "length": length,
                    "count": len(items),
                    "headers": sorted({item["header"] for item in items}),
                    "unique_length_constants": len(constants),
                    "length_constants": [f"0x{value:04x}" for value in constants],
                    "compatible_with_fixed_length_constant": len(constants) == 1,
                    "records": items[:10],
                }
            )
        return rows

    def integrity_ccitt_offset_scan(self) -> list[dict[str, object]]:
        grouped: dict[tuple[str, int], list[dict[str, object]]] = {}
        for row in self._matching_integrity_records():
            grouped.setdefault((row["header"], row["length"]), []).append(row)

        rows = []
        for (header, length), items in sorted(grouped.items()):
            if len(items) < 2:
                continue
            offset_rows = []
            for start in range(0, min(12, length - 1)):
                constants = []
                for item in items:
                    decrypted = item["decrypted"]
                    if start >= len(decrypted) - 2:
                        continue
                    crc_zero = _crc16_zero_poly(
                        decrypted[start:-2],
                        poly=0x1021,
                        refin=False,
                        refout=False,
                    )
                    constants.append(item["stream_tail"] ^ crc_zero)
                unique_constants = sorted(set(constants))
                offset_rows.append(
                    {
                        "start": start,
                        "unique_constants": len(unique_constants),
                        "constants": [f"0x{value:04x}" for value in unique_constants[:8]],
                    }
                )
            best = min(offset_rows, key=lambda row: (row["unique_constants"], row["start"]))
            uniform_starts = [
                row["start"] for row in offset_rows if row["unique_constants"] == best["unique_constants"]
            ]
            preferred_start = best["start"]
            for candidate in (4, 2):
                if candidate in uniform_starts:
                    preferred_start = candidate
                    break
            preferred_row = next(
                row for row in offset_rows if row["start"] == preferred_start
            )
            rows.append(
                {
                    "header": header,
                    "header_name": HEADER_NAMES.get(header, "unknown"),
                    "length": length,
                    "count": len(items),
                    "best_start": best["start"],
                    "best_unique_constants": best["unique_constants"],
                    "best_constants": best["constants"],
                    "uniform_starts": uniform_starts,
                    "preferred_start": preferred_start,
                    "preferred_constants": preferred_row["constants"],
                    "offset_rows": offset_rows,
                }
            )
        return rows

    def integrity_differential_crc16_search(self) -> dict[str, object]:
        grouped: dict[int, list[dict[str, object]]] = {}
        for row in self._matching_integrity_records():
            grouped.setdefault(row["length"], []).append(row)

        selected_length = None
        selected_records: list[dict[str, object]] = []
        for length, rows in sorted(grouped.items(), key=lambda item: (item[0], -len(item[1]))):
            distinct_bodies = {row["decrypted"][:-2] for row in rows}
            if len(rows) >= 4 and len(distinct_bodies) >= 2:
                selected_length = length
                selected_records = rows[:7]
                break

        if selected_length is None:
            return {
                "selected_length": None,
                "selected_sids": [],
                "selected_headers": [],
                "pair_count": 0,
                "results": [],
            }

        def _input_variants(record: dict[str, object]) -> dict[str, bytes]:
            raw = record["raw"]
            decrypted = record["decrypted"]
            return {
                "dec_wo_tail": decrypted[:-2],
                "logical_full_wo_tail": raw[:2] + decrypted[:-2],
                "raw_wo_tail": raw[:-2],
            }

        selected_inputs = [_input_variants(row) for row in selected_records]
        pair_indexes = []
        limit = len(selected_records)
        for left in range(limit):
            for right in range(left + 1, limit):
                pair_indexes.append((left, right))
        pair_indexes = pair_indexes[:8]

        results = []
        for input_name in ["dec_wo_tail", "logical_full_wo_tail", "raw_wo_tail"]:
            for refin in (False, True):
                for refout in (False, True):
                    survivors = list(range(1, 0x10000))
                    pair_progress = []
                    for left, right in pair_indexes:
                        desired_diff = (
                            selected_records[left]["stream_tail"] ^ selected_records[right]["stream_tail"]
                        )
                        filtered = []
                        left_data = selected_inputs[left][input_name]
                        right_data = selected_inputs[right][input_name]
                        for poly in survivors:
                            left_crc = _crc16_zero_poly(left_data, poly=poly, refin=refin, refout=refout)
                            right_crc = _crc16_zero_poly(right_data, poly=poly, refin=refin, refout=refout)
                            if (left_crc ^ right_crc) == desired_diff:
                                filtered.append(poly)
                        survivors = filtered
                        pair_progress.append(
                            {
                                "pair": [selected_records[left]["sid"], selected_records[right]["sid"]],
                                "survivors": len(survivors),
                            }
                        )
                        if not survivors:
                            break
                    results.append(
                        {
                            "input": input_name,
                            "refin": refin,
                            "refout": refout,
                            "survivor_count": len(survivors),
                            "survivor_sample": [f"0x{poly:04x}" for poly in survivors[:12]],
                            "pair_progress": pair_progress,
                        }
                    )

        return {
            "selected_length": selected_length,
            "selected_sids": [row["sid"] for row in selected_records],
            "selected_headers": [row["header"] for row in selected_records],
            "pair_count": len(pair_indexes),
            "results": results,
        }

    def integrity_summary(self) -> dict[str, object]:
        directory_by_sid = {row["sid"]: row for row in self.directory_entries()}
        rows = []
        matching_records = []
        header_totals: Counter[str] = Counter()
        header_matches: Counter[str] = Counter()
        for sid, raw in sorted(self.streams.items()):
            if sid not in directory_by_sid or sid not in self.decrypted_streams:
                continue
            decrypted = self.decrypted_streams[sid]
            if len(decrypted) < 2:
                continue
            stream_tail = int.from_bytes(decrypted[-2:], "big")
            directory_crc = directory_by_sid[sid]["crc"]
            matches = directory_crc == stream_tail
            header = raw[:2].hex()
            header_totals[header] += 1
            if matches:
                header_matches[header] += 1
                if len(decrypted) >= 4:
                    matching_records.append((raw, decrypted, stream_tail))
            rows.append(
                {
                    "sid": sid,
                    "header": header,
                    "length": len(decrypted),
                    "directory_crc": directory_crc,
                    "directory_crc_hex": f"0x{directory_crc:04x}",
                    "stream_tail": stream_tail,
                    "stream_tail_hex": f"0x{stream_tail:04x}",
                    "matches": matches,
                }
            )

        crc_input_variants = {
            "dec_wo_tail": lambda raw, decrypted: decrypted[:-2],
            "raw_wo_tail": lambda raw, decrypted: raw[:-2],
            "raw_body_wo_tail": lambda raw, decrypted: raw[2:-2],
        }
        crc_candidates = []
        for input_name, getter in crc_input_variants.items():
            for variant_name, params in COMMON_CRC16_VARIANTS.items():
                match_count = 0
                for raw, decrypted, stream_tail in matching_records:
                    if _crc16_variant(getter(raw, decrypted), **params) == stream_tail:
                        match_count += 1
                if match_count:
                    crc_candidates.append(
                        {
                            "input": input_name,
                            "variant": variant_name,
                            "matches": match_count,
                            "total": len(matching_records),
                        }
                    )
        crc_candidates.sort(key=lambda row: (-row["matches"], row["input"], row["variant"]))

        per_header = []
        for header, total in sorted(header_totals.items()):
            per_header.append(
                {
                    "header": header,
                    "header_name": HEADER_NAMES.get(header, "unknown"),
                    "matches": header_matches.get(header, 0),
                    "total": total,
                }
            )

        return {
            "directory_tail_matches": sum(1 for row in rows if row["matches"]),
            "directory_tail_total": len(rows),
            "matching_record_count": len(matching_records),
            "mismatches": [row for row in rows if not row["matches"]],
            "per_header": per_header,
            "common_crc16_candidates": crc_candidates,
            "ccitt_profile": self.integrity_ccitt_profile(),
            "ccitt_offset_scan": self.integrity_ccitt_offset_scan(),
            "differential_crc16_search": self.integrity_differential_crc16_search(),
        }

    def c7_tail_patterns(self) -> list[dict[str, object]]:
        rows = []
        for row in self.extended_c7_blocks():
            decrypted = self.decrypted_streams[row["sid"]]
            header_bytes = bytes.fromhex(row["header_hex"]) if row["header_hex"] else b""
            header_tail_word = (
                struct.unpack_from(">H", header_bytes, len(header_bytes) - 2)[0]
                if len(header_bytes) >= 2
                else None
            )
            final_tail_word = int.from_bytes(decrypted[-2:], "big") if len(decrypted) >= 2 else None
            nonfinal_tails = Counter(
                block["tail_hex"]
                for block in row["blocks"][:-1]
                if block.get("tail_hex") is not None
            )
            rows.append(
                {
                    "sid": row["sid"],
                    "record_index": row["record_index"],
                    "length": row["length"],
                    "header_length": row["header_length"],
                    "header_tail_word": header_tail_word,
                    "header_tail_word_hex": f"0x{header_tail_word:04x}" if header_tail_word is not None else None,
                    "final_stream_tail_word": final_tail_word,
                    "final_stream_tail_word_hex": f"0x{final_tail_word:04x}" if final_tail_word is not None else None,
                    "final_block_tail_hex": row["blocks"][-1]["tail_hex"] if row["blocks"] else "",
                    "nonfinal_tail_patterns": [
                        {"tail_hex": tail_hex, "count": count}
                        for tail_hex, count in nonfinal_tails.most_common(6)
                    ],
                }
            )
        return rows

    def c7_ccitt_profile(self) -> list[dict[str, object]]:
        grouped: dict[int, list[dict[str, object]]] = {}
        for sid, raw in sorted(self.streams.items()):
            if raw[:2].hex() != "84c7":
                continue
            decrypted = self.decrypted_streams[sid]
            if len(decrypted) < 6:
                continue
            tail = int.from_bytes(decrypted[-2:], "big")
            crc_zero = _crc16_zero_poly(
                decrypted[4:-2],
                poly=0x1021,
                refin=False,
                refout=False,
            )
            grouped.setdefault(len(decrypted), []).append(
                {
                    "sid": sid,
                    "record_index": struct.unpack_from(">H", decrypted, 0)[0],
                    "tail": tail,
                    "tail_hex": f"0x{tail:04x}",
                    "ccitt_crc_from_offset_4": crc_zero,
                    "ccitt_crc_from_offset_4_hex": f"0x{crc_zero:04x}",
                    "length_constant": tail ^ crc_zero,
                    "length_constant_hex": f"0x{(tail ^ crc_zero):04x}",
                }
            )

        rows = []
        for length, items in sorted(grouped.items()):
            constants = sorted({item["length_constant"] for item in items})
            rows.append(
                {
                    "length": length,
                    "count": len(items),
                    "unique_length_constants": len(constants),
                    "length_constants": [f"0x{value:04x}" for value in constants],
                    "records": items,
                }
            )
        return rows

    def c7_ccitt_offset_scan(self) -> list[dict[str, object]]:
        grouped: dict[int, list[dict[str, object]]] = {}
        for sid, raw in sorted(self.streams.items()):
            if raw[:2].hex() != "84c7":
                continue
            decrypted = self.decrypted_streams[sid]
            if len(decrypted) < 6:
                continue
            grouped.setdefault(len(decrypted), []).append(
                {
                    "sid": sid,
                    "record_index": struct.unpack_from(">H", decrypted, 0)[0],
                    "tail": int.from_bytes(decrypted[-2:], "big"),
                    "decrypted": decrypted,
                }
            )

        rows = []
        for length, items in sorted(grouped.items()):
            offset_rows = []
            for start in range(0, min(12, length - 1)):
                constants = []
                for item in items:
                    decrypted = item["decrypted"]
                    if start >= len(decrypted) - 2:
                        continue
                    crc_zero = _crc16_zero_poly(
                        decrypted[start:-2],
                        poly=0x1021,
                        refin=False,
                        refout=False,
                    )
                    constants.append(item["tail"] ^ crc_zero)
                unique_constants = sorted(set(constants))
                offset_rows.append(
                    {
                        "start": start,
                        "unique_constants": len(unique_constants),
                        "constants": [f"0x{value:04x}" for value in unique_constants[:8]],
                    }
                )
            best = min(offset_rows, key=lambda row: (row["unique_constants"], row["start"]))
            uniform_starts = [
                row["start"] for row in offset_rows if row["unique_constants"] == best["unique_constants"]
            ]
            preferred_start = best["start"]
            for candidate in (4, 2):
                if candidate in uniform_starts:
                    preferred_start = candidate
                    break
            preferred_row = next(
                row for row in offset_rows if row["start"] == preferred_start
            )
            rows.append(
                {
                    "length": length,
                    "count": len(items),
                    "best_start": best["start"],
                    "best_unique_constants": best["unique_constants"],
                    "best_constants": best["constants"],
                    "uniform_starts": uniform_starts,
                    "preferred_start": preferred_start,
                    "preferred_constants": preferred_row["constants"],
                    "offset_rows": offset_rows,
                    "records": [
                        {
                            "sid": item["sid"],
                            "record_index": item["record_index"],
                            "tail_hex": f"0x{item['tail']:04x}",
                        }
                        for item in items[:10]
                    ],
                }
            )
        return rows

    def c7_directory_delta_profile(self) -> list[dict[str, object]]:
        directory_by_sid = {row["sid"]: row for row in self.directory_entries()}
        grouped: dict[int, list[dict[str, object]]] = {}
        for sid, raw in sorted(self.streams.items()):
            if raw[:2].hex() != "84c7" or sid not in directory_by_sid:
                continue
            decrypted = self.decrypted_streams[sid]
            if len(decrypted) < 2:
                continue
            tail = int.from_bytes(decrypted[-2:], "big")
            directory_crc = directory_by_sid[sid]["crc"]
            delta = (directory_crc - tail) & 0xFFFF
            grouped.setdefault(len(decrypted), []).append(
                {
                    "sid": sid,
                    "record_index": struct.unpack_from(">H", decrypted, 0)[0],
                    "directory_crc_hex": f"0x{directory_crc:04x}",
                    "tail_hex": f"0x{tail:04x}",
                    "delta": delta,
                    "delta_hex": f"0x{delta:04x}",
                }
            )

        rows = []
        for length, items in sorted(grouped.items()):
            delta_values = sorted({item["delta"] for item in items})
            rows.append(
                {
                    "length": length,
                    "count": len(items),
                    "unique_deltas": len(delta_values),
                    "deltas": [f"0x{value:04x}" for value in delta_values[:8]],
                    "records": items[:10],
                }
            )
        return rows

    def deep_analysis(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "variant": self.classify_variant(),
            "directory_entries": self.directory_entries(),
            "unknown_headers": self.unknown_header_inventory(),
            "text_payload_records": self.text_payload_records(),
            "support_cluster_records": self.support_cluster_records(),
            "global_text_tables": self.global_text_tables(),
            "zone_label_tables": self.zone_label_tables(),
            "zone_companions": self.zone_companion_records(),
            "zone_controls": self.zone_control_records(),
            "personality_variants": self.personality_variants(),
            "channel_configs": self.channel_configs(),
            "scan_list_members": self.scan_list_members(),
            "channel_group_refs": self.channel_group_refs(),
            "extended_c7_blocks": self.extended_c7_blocks(),
            "c7_tail_patterns": self.c7_tail_patterns(),
            "c7_ccitt_profile": self.c7_ccitt_profile(),
            "c7_ccitt_offset_scan": self.c7_ccitt_offset_scan(),
            "c7_directory_delta_profile": self.c7_directory_delta_profile(),
            "integrity_summary": self.integrity_summary(),
        }

    def inferred_channel_inventory(self) -> list[dict[str, object]]:
        c7_by_zone: dict[int, list[dict[str, object]]] = {}
        c7_by_record_index: dict[int, dict[str, object]] = {}
        for row in self.extended_c7_blocks():
            c7_by_record_index[row["record_index"]] = row
            zone_index = row["record_index"] // 2
            c7_by_zone.setdefault(zone_index, []).append(row)
        for rows in c7_by_zone.values():
            rows.sort(key=lambda item: item["record_index"])
        c6_by_record_index = {
            row["record_index"]: row
            for row in self.zone_companion_records()
            if row["header"] == "84c6"
        }
        c4_by_record_index = {
            row["record_index"]: row
            for row in self.zone_companion_records()
            if row["header"] == "84c4"
        }

        inventory = []
        for table in self.zone_label_tables():
            zone_index = table["record_index"]
            pairing_source = "record_index_heuristic"
            paired_rows = c7_by_zone.get(zone_index, [])
            c6_companion = c6_by_record_index.get(zone_index)
            c4_companion = c4_by_record_index.get(zone_index)
            classification = "zone_table"
            if c4_companion is None and c6_companion is None:
                classification = "unpaired_text_table"
                pairing_source = "none"
                paired_rows = []
            if c6_companion and c6_companion.get("c7_base_record_index") is not None:
                base_index = c6_companion["c7_base_record_index"]
                direct_rows = [
                    c7_by_record_index[index]
                    for index in [base_index, base_index + 1]
                    if index in c7_by_record_index
                ]
                if direct_rows:
                    paired_rows = direct_rows
                    pairing_source = "84c6"

            paired_blocks = []
            for row in paired_rows:
                paired_blocks.extend(row["blocks"])
            standard_blocks = [
                {
                    "record_sid": row["sid"],
                    "record_index": row["record_index"],
                    "block_index": block["index"],
                    "entry_index": block["entry_index"],
                    "frequency_values": block["frequency_values"],
                    "profile_hint": block["profile_hint"],
                }
                for row in paired_rows
                for block in row["blocks"]
                if block["block_class"] == "standard"
            ]
            ordered_visible_blocks: list[dict[str, object]] = []
            if len(standard_blocks) == len(table["labels"]):
                ordered_visible_blocks = standard_blocks
            elif (
                len(standard_blocks) == len(table["labels"]) + 1
                and standard_blocks
                and standard_blocks[0]["profile_hint"] == "split_pair_like"
            ):
                ordered_visible_blocks = standard_blocks[1:]

            channel_count = max(len(table["labels"]), len(paired_blocks))
            channels = []
            for channel_index in range(channel_count):
                label_entry = table["labels"][channel_index] if channel_index < len(table["labels"]) else None
                label_text = label_entry["text"] if label_entry else None
                label_freq_match = (
                    re.search(r"\b(1[34]\d\.\d{3})\b", label_text) if label_text else None
                )
                label_frequency_mhz = float(label_freq_match.group(1)) if label_freq_match else None
                ordered_c7_entry = (
                    ordered_visible_blocks[channel_index]
                    if channel_index < len(ordered_visible_blocks)
                    else None
                )
                c7_matches = []
                if label_frequency_mhz is not None:
                    for block in standard_blocks:
                        matched_fields = [
                            item["field"]
                            for item in block["frequency_values"]
                            if item["mhz"] is not None and abs(item["mhz"] - label_frequency_mhz) < 0.001
                        ]
                        if matched_fields:
                            c7_matches.append(
                                {
                                    "record_sid": block["record_sid"],
                                    "record_index": block["record_index"],
                                    "block_index": block["block_index"],
                                    "entry_index": block["entry_index"],
                                    "matched_fields": matched_fields,
                                    "profile_hint": block["profile_hint"],
                                }
                            )
                elif label_text and label_text.upper() == "APRS":
                    for block in standard_blocks:
                        if block["profile_hint"] == "simplex_packet_like":
                            c7_matches.append(
                                {
                                    "record_sid": block["record_sid"],
                                    "record_index": block["record_index"],
                                    "block_index": block["block_index"],
                                    "entry_index": block["entry_index"],
                                    "matched_fields": [
                                        item["field"]
                                        for item in block["frequency_values"]
                                        if item["mhz"] is not None and abs(item["mhz"] - 144.390) < 0.001
                                    ],
                                    "profile_hint": block["profile_hint"],
                                }
                            )
                channels.append(
                    {
                        "index": channel_index,
                        "label": label_text,
                        "label_frequency_mhz": label_frequency_mhz,
                        "raw_hex": label_entry["raw_hex"] if label_entry else None,
                        "non_ascii_bytes": label_entry["non_ascii_bytes"] if label_entry else [],
                        "ordered_c7_entry": ordered_c7_entry,
                        "c7_matches": c7_matches,
                    }
                )

            inventory.append(
                {
                    "zone_index": zone_index,
                    "table_sid": table["sid"],
                    "zone_label": table["zone_label"] or f"Zone {zone_index + 1}",
                    "channels": channels,
                    "c7_record_sids": [row["sid"] for row in paired_rows],
                    "pairing_source": pairing_source,
                    "pairing_confirmed": pairing_source == "84c6",
                    "classification": classification,
                    "layout_source": table.get("layout_source"),
                    "label_base_offset": table.get("label_base_offset"),
                    "slot_width": table.get("slot_width"),
                    "slot_count": table.get("slot_count"),
                    "c6_companion_sid": c6_companion["sid"] if c6_companion else None,
                    "c4_companion_sid": c4_companion["sid"] if c4_companion else None,
                    "c7_entries": [
                        {
                            "record_sid": row["sid"],
                            "record_index": row["record_index"],
                            "block_index": block["index"],
                            "block_class": block["block_class"],
                            "entry_kind": block["entry_kind"],
                            "entry_code": block["entry_code"],
                            "entry_index": block["entry_index"],
                            "entry_frequency_mhz": round(block["entry_frequency_mhz"], 3)
                            if block["entry_frequency_mhz"] is not None
                            else None,
                            "ctcss_candidate_hz": round(block["ctcss_candidate_hz"], 1)
                            if block.get("ctcss_candidate_hz") is not None
                            else None,
                            "entry_ref": block["entry_ref"],
                            "selector": block["selector"],
                            "selector_frequency_mhz": round(block["selector_frequency_mhz"], 3)
                            if block["selector_frequency_mhz"] is not None
                            else None,
                            "value_a_hex": block["value_a_hex"],
                            "value_b_hex": block["value_b_hex"],
                            "value_c_hex": block["value_c_hex"],
                            "frequency_values": block["frequency_values"],
                            "value_pattern": block["value_pattern"],
                            "profile_hint": block["profile_hint"],
                        }
                        for row in paired_rows
                        for block in row["blocks"]
                    ],
                }
            )
        return inventory

    def summary(self) -> dict[str, object]:
        identity = self.radio_identity()
        directory = self.directory_entries()
        directory_freqs = [
            entry
            for entry in directory
            if entry["sid"] != 0 and entry["extra"]["kind"] == "frequency" and entry["sid"] in self.streams
        ]
        directory_ctcss = [
            entry
            for entry in directory
            if entry["sid"] != 0 and entry["extra"]["kind"] == "ctcss" and entry["sid"] in self.streams
        ]
        return {
            "path": str(self.path),
            "stream_count": len(self.streams),
            "key_prefix_hex": " ".join(f"{byte:02x}" for byte in self.key[:12]),
            "identity": identity,
            "metadata_candidates": self.metadata_candidates(),
            "stream_counts": self.stream_counts(),
            "channel_names": self.channel_names(),
            "text_payload_records": self.text_payload_records(),
            "support_cluster_records": self.support_cluster_records(),
            "global_text_tables": self.global_text_tables(),
            "personalities": self.personalities(),
            "personality_variants": self.personality_variants(),
            "channel_configs": self.channel_configs(),
            "scan_list_members": self.scan_list_members(),
            "zone_controls": self.zone_control_records(),
            "tone_blocks": self.tone_blocks(),
            "directory": {
                "entries": len(directory),
                "frequency_entries": directory_freqs,
                "ctcss_entries": directory_ctcss,
            },
        }


def load_codeplug(path: str | Path) -> Astro25Codeplug:
    return Astro25Codeplug(path)
