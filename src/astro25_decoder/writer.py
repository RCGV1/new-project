from __future__ import annotations

import shutil
import struct
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import olefile

from .decoder import (
    CTCSS,
    Astro25Codeplug,
    _crc16_zero_poly,
    _encode_u32_freq_value,
)


TAIL_MODELS: dict[str, dict[tuple[str, int], tuple[int, int]]] = {
    "legacy_single_zone": {
        ("84c4", 18): (4, 0xB861),
        ("84c5", 29): (4, 0xF031),
        ("84c6", 21): (4, 0x6F45),
        ("84c7", 46): (4, 0x6735),
        ("84c7", 47): (4, 0x2941),
        ("84ca", 57): (4, 0xA8F9),
        ("84cb", 35): (4, 0x3703),
        ("84cb", 36): (4, 0x45B4),
        ("8b7d", 50): (4, 0x26AA),
    },
    "w6slg_multizone_variant": {
        ("84c4", 18): (4, 0x0000),
        ("84c5", 284): (4, 0x0000),
        ("84c6", 21): (4, 0x0000),
        ("84c7", 222): (4, 0x0000),
        ("84c7", 362): (4, 0xB152),
        ("84ca", 57): (4, 0x0000),
        ("84cb", 36): (4, 0x0000),
        ("8b7d", 50): (4, 0x0000),
    },
    "multizone_compact_labels": {
        ("84c4", 18): (4, 0x377B),
        ("84c6", 21): (4, 0x9496),
        ("84c7", 222): (4, 0x2001),
        ("84c7", 362): (4, 0x4E74),
        ("84ca", 57): (4, 0x6B7A),
        ("84cb", 36): (4, 0x1BC4),
    },
}


class Astro25WriteError(ValueError):
    pass


@dataclass
class ChannelPatch:
    zone: int
    slot: int
    label: str | None = None
    rx_mhz: float | None = None
    tx_mhz: float | None = None
    tx_pl_hz: float | None = None


@dataclass
class WriteReport:
    input_path: str
    output_path: str
    family: str
    edited_streams: list[int] = field(default_factory=list)
    directory_updates: list[int] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _ctcss_index(hz: float) -> int:
    for index, value in enumerate(CTCSS):
        if abs(value - hz) < 0.05:
            return index
    raise Astro25WriteError(f"unsupported CTCSS tone {hz}")


def _ensure_ascii_label(label: str, width: int) -> bytes:
    encoded = label.encode("ascii")
    if len(encoded) > width:
        raise Astro25WriteError(f"label '{label}' exceeds slot width {width}")
    return encoded + (b"\x00" * (width - len(encoded)))


def _encode_bcd_byte(value: int) -> int:
    if value < 0 or value > 99:
        raise Astro25WriteError(f"value {value} is out of BCD byte range")
    return ((value // 10) << 4) | (value % 10)


class Astro25CodeplugWriter:
    def __init__(self, path: str | Path):
        self.codeplug = Astro25Codeplug(path)
        self.path = Path(path)
        self.family = self.codeplug.classify_variant()["family"]
        self.mutable_streams: dict[int, bytearray] = {
            sid: bytearray(data) for sid, data in self.codeplug.decrypted_streams.items()
        }
        self.inventory = self.codeplug.inferred_channel_inventory()
        self.c7_rows = {row["sid"]: row for row in self.codeplug.extended_c7_blocks()}
        self.directory_by_sid = {
            row["sid"]: row for row in self.codeplug.directory_entries()
        }
        self.directory_stream_sid = 0 if 0 in self.mutable_streams else None
        self.touched_sids: set[int] = set()
        self.directory_updates: set[int] = set()
        self.warnings: list[str] = []
        self.notes: list[str] = []

    def _mark_touched(self, sid: int) -> None:
        self.touched_sids.add(sid)

    def _stream_header(self, sid: int) -> str:
        return self.codeplug.streams[sid][:2].hex()

    def _tail_model(self, sid: int) -> tuple[int, int]:
        header = self._stream_header(sid)
        length = len(self.mutable_streams[sid])
        family_models = TAIL_MODELS.get(self.family, {})
        model = family_models.get((header, length))
        if model is None:
            raise Astro25WriteError(
                f"no tail model for family={self.family} header={header} len={length} sid={sid}"
            )
        return model

    def _recompute_stream_tail(self, sid: int) -> int:
        start, constant = self._tail_model(sid)
        data = bytes(self.mutable_streams[sid])
        if len(data) <= start + 2:
            raise Astro25WriteError(f"stream {sid} too short to recompute tail")
        crc_zero = _crc16_zero_poly(
            data[start:-2],
            poly=0x1021,
            refin=False,
            refout=False,
        )
        tail = crc_zero ^ constant
        self.mutable_streams[sid][-2:] = tail.to_bytes(2, "big")
        return tail

    def _update_directory_crc(self, sid: int) -> None:
        if self.directory_stream_sid is None or sid not in self.directory_by_sid:
            return
        directory = self.mutable_streams[self.directory_stream_sid]
        entry = self.directory_by_sid[sid]
        tail = int.from_bytes(self.mutable_streams[sid][-2:], "big")
        if (
            self.family == "w6slg_multizone_variant"
            and self._stream_header(sid) == "84c5"
            and entry.get("record_index_word") == 0
        ):
            tail ^= 0x0100
        offset = entry["entry"] * 10 + 4
        directory[offset : offset + 2] = tail.to_bytes(2, "big")
        self.directory_updates.add(sid)

    def _update_save_metadata(self, save_datetime: datetime | None = None) -> None:
        target = (save_datetime or datetime.now().astimezone()).replace(second=0, microsecond=0)
        touched = 0
        for sid, raw in sorted(self.codeplug.streams.items()):
            if raw[:2].hex() != "8b7d":
                continue
            data = self.mutable_streams[sid]
            if len(data) != 50:
                self.warnings.append(
                    f"skipped unsupported 8b7d save metadata layout sid={sid} len={len(data)}"
                )
                continue
            data[4] = _encode_bcd_byte(target.year % 100)
            data[5] = _encode_bcd_byte(target.month)
            data[6] = _encode_bcd_byte(target.day)
            data[7] = _encode_bcd_byte(target.hour)
            data[8] = _encode_bcd_byte(target.minute)
            self._mark_touched(sid)
            touched += 1
            self.notes.append(
                f"updated save metadata sid={sid} timestamp={target.strftime('%Y-%m-%d %H:%M')}"
            )
        if touched == 0:
            self.notes.append("no writable 8b7d save metadata streams were found")

    def _locate_channel(self, zone: int, slot: int) -> tuple[dict[str, object], dict[str, object]]:
        if zone < 1 or zone > len(self.inventory):
            raise Astro25WriteError(f"zone {zone} out of range")
        zone_row = self.inventory[zone - 1]
        channels = zone_row["channels"]
        if slot < 1 or slot > len(channels):
            raise Astro25WriteError(f"slot {slot} out of range for zone {zone}")
        return zone_row, channels[slot - 1]

    def _set_label(self, zone_row: dict[str, object], channel_row: dict[str, object], label: str) -> None:
        sid = zone_row["table_sid"]
        table = next(
            table for table in self.codeplug.zone_label_tables() if table["sid"] == sid
        )
        slot_width = table.get("slot_width")
        slot_offset = channel_row["index"] * slot_width + table["label_base_offset"]
        if slot_width is None or table.get("label_base_offset") is None:
            raise Astro25WriteError(f"cannot write label into sid {sid}: layout unknown")
        self.mutable_streams[sid][slot_offset : slot_offset + slot_width] = _ensure_ascii_label(label, slot_width)
        self._mark_touched(sid)

    def _patch_u32_freq(self, chunk: bytearray, offset: int, mhz: float) -> None:
        current = int.from_bytes(chunk[offset : offset + 4], "big")
        high_bit = current & 0x80000000
        value = _encode_u32_freq_value(mhz) | high_bit
        chunk[offset : offset + 4] = value.to_bytes(4, "big")

    def _set_c7_frequencies(
        self,
        sid: int,
        block_index: int,
        *,
        rx_mhz: float | None,
        tx_mhz: float | None,
    ) -> None:
        row = self.c7_rows[sid]
        block = row["blocks"][block_index]
        data = self.mutable_streams[sid]
        block_offset = row["header_length"] + block_index * 35
        chunk = bytearray(data[block_offset : block_offset + 35])
        if block["frequency_mapping_hint"] == "simplex_shared":
            target = rx_mhz if rx_mhz is not None else tx_mhz
            if target is None:
                return
            if rx_mhz is not None and tx_mhz is not None and abs(rx_mhz - tx_mhz) >= 0.001:
                raise Astro25WriteError(
                    "simplex_shared entries cannot take different rx/tx frequencies"
                )
            for offset in (10, 14, 18):
                self._patch_u32_freq(chunk, offset, target)
        elif block["frequency_mapping_hint"] == "a_is_tx_b_c_is_rx":
            current_tx = block.get("likely_tx_mhz")
            current_rx = block.get("likely_rx_mhz")
            target_tx = tx_mhz if tx_mhz is not None else current_tx
            target_rx = rx_mhz if rx_mhz is not None else current_rx
            if target_tx is None or target_rx is None:
                raise Astro25WriteError("cannot infer current rx/tx values for paired entry")
            self._patch_u32_freq(chunk, 10, target_tx)
            self._patch_u32_freq(chunk, 14, target_rx)
            self._patch_u32_freq(chunk, 18, target_rx)
        elif rx_mhz is not None or tx_mhz is not None:
            raise Astro25WriteError(
                f"unsupported c7 frequency mapping for sid={sid} block={block_index}"
            )
        data[block_offset : block_offset + 35] = chunk
        self._mark_touched(sid)

    def _set_c7_tx_pl_legacy_single_zone(
        self,
        sid: int,
        block_index: int,
        tone_index: int,
    ) -> None:
        row = self.c7_rows[sid]
        data = self.mutable_streams[sid]
        block_offset = row["header_length"] + block_index * 35
        data[block_offset + 22] = tone_index
        self._mark_touched(sid)

    def _set_c7_tx_pl_w6slg_multizone(
        self,
        zone_row: dict[str, object],
        channel_row: dict[str, object],
        tone_index: int,
    ) -> None:
        # CPS-authored sample showed the tx PL for a split-pair channel landing in the
        # next ordered entry's flag0/flag2 bytes. This is still experimental.
        channels = zone_row["channels"]
        target_index = channel_row["index"] + 1
        target_entry = None
        if target_index < len(channels):
            target_entry = channels[target_index].get("ordered_c7_entry")
        if target_entry is None:
            target_entry = channel_row.get("ordered_c7_entry")
        if target_entry is None:
            raise Astro25WriteError("cannot locate c7 entry for experimental tx PL patch")
        sid = target_entry["record_sid"]
        row = self.c7_rows[sid]
        block_index = target_entry["block_index"]
        data = self.mutable_streams[sid]
        block_offset = row["header_length"] + block_index * 35
        data[block_offset + 22] = tone_index
        data[block_offset + 24] = tone_index
        self._mark_touched(sid)
        self.warnings.append(
            "used experimental W6SLG multizone tx PL heuristic (next entry flag bytes)"
        )

    def _set_tx_pl(
        self,
        zone_row: dict[str, object],
        channel_row: dict[str, object],
        tx_pl_hz: float,
    ) -> None:
        tone_index = _ctcss_index(tx_pl_hz)
        ordered = channel_row.get("ordered_c7_entry")
        if ordered is None:
            raise Astro25WriteError("channel has no ordered c7 entry for tx PL patch")
        sid = ordered["record_sid"]
        row = self.c7_rows[sid]
        block = row["blocks"][ordered["block_index"]]
        if self.family == "legacy_single_zone" and row["length"] == 47:
            self._set_c7_tx_pl_legacy_single_zone(sid, ordered["block_index"], tone_index)
            return
        if self.family == "w6slg_multizone_variant" and block["profile_hint"] in {
            "split_pair_like",
            "paired_frequency_like",
        }:
            self._set_c7_tx_pl_w6slg_multizone(zone_row, channel_row, tone_index)
            return
        raise Astro25WriteError(
            f"tx PL writing is not yet supported for family={self.family} sid={sid} len={row['length']}"
        )

    def apply_channel_patch(
        self,
        patch: ChannelPatch,
        *,
        touch_save_metadata: bool = True,
        save_datetime: datetime | None = None,
    ) -> WriteReport:
        zone_row, channel_row = self._locate_channel(patch.zone, patch.slot)
        if patch.label is None and patch.rx_mhz is None and patch.tx_mhz is None and patch.tx_pl_hz is None:
            raise Astro25WriteError("no patch fields were provided")

        if patch.label is not None:
            self._set_label(zone_row, channel_row, patch.label)
            self.notes.append(f"updated label in sid={zone_row['table_sid']}")

        ordered = channel_row.get("ordered_c7_entry")
        if ordered is None and (patch.rx_mhz is not None or patch.tx_mhz is not None or patch.tx_pl_hz is not None):
            raise Astro25WriteError("channel has no ordered c7 entry")

        if ordered is not None and (patch.rx_mhz is not None or patch.tx_mhz is not None):
            self._set_c7_frequencies(
                ordered["record_sid"],
                ordered["block_index"],
                rx_mhz=patch.rx_mhz,
                tx_mhz=patch.tx_mhz,
            )
            self.notes.append(
                f"updated c7 sid={ordered['record_sid']} block={ordered['block_index']} frequencies"
            )

        if patch.tx_pl_hz is not None:
            self._set_tx_pl(zone_row, channel_row, patch.tx_pl_hz)
            self.notes.append(f"updated tx PL to {patch.tx_pl_hz:.1f} Hz")

        if touch_save_metadata:
            self._update_save_metadata(save_datetime=save_datetime)

        for sid in sorted(self.touched_sids):
            if sid == self.directory_stream_sid:
                continue
            self._recompute_stream_tail(sid)
        for sid in sorted(self.touched_sids):
            if sid == self.directory_stream_sid:
                continue
            self._update_directory_crc(sid)

        output_path = self.path
        return WriteReport(
            input_path=str(self.path),
            output_path=str(output_path),
            family=self.family,
            edited_streams=sorted(self.touched_sids),
            directory_updates=sorted(self.directory_updates),
            warnings=self.warnings[:],
            notes=self.notes[:],
        )

    def write(self, output_path: str | Path) -> WriteReport:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.path, output)
        with olefile.OleFileIO(str(output), write_mode=True) as ole:
            sids_to_write = set(self.touched_sids)
            if self.directory_updates and self.directory_stream_sid is not None:
                sids_to_write.add(self.directory_stream_sid)
            for sid in sorted(sids_to_write):
                encrypted = self._encrypt_stream(sid, bytes(self.mutable_streams[sid]))
                ole.write_stream(f"DataStg/Strm_{sid}", encrypted)
        return WriteReport(
            input_path=str(self.path),
            output_path=str(output),
            family=self.family,
            edited_streams=sorted(self.touched_sids),
            directory_updates=sorted(self.directory_updates),
            warnings=self.warnings[:],
            notes=self.notes[:],
        )

    def _encrypt_stream(self, sid: int, decrypted: bytes) -> bytes:
        raw = self.codeplug.streams[sid]
        if len(raw) != len(decrypted) + 2:
            raise Astro25WriteError(f"stream {sid} size mismatch during encryption")
        body = bytes(
            decrypted[idx] ^ self.codeplug.key[idx]
            if idx < len(self.codeplug.key)
            else decrypted[idx]
            for idx in range(len(decrypted))
        )
        return raw[:2] + body


def write_channel(
    input_path: str | Path,
    output_path: str | Path,
    *,
    zone: int,
    slot: int,
    label: str | None = None,
    rx_mhz: float | None = None,
    tx_mhz: float | None = None,
    tx_pl_hz: float | None = None,
    touch_save_metadata: bool = True,
    save_datetime: datetime | None = None,
) -> WriteReport:
    writer = Astro25CodeplugWriter(input_path)
    writer.apply_channel_patch(
        ChannelPatch(
            zone=zone,
            slot=slot,
            label=label,
            rx_mhz=rx_mhz,
            tx_mhz=tx_mhz,
            tx_pl_hz=tx_pl_hz,
        ),
        touch_save_metadata=touch_save_metadata,
        save_datetime=save_datetime,
    )
    return writer.write(output_path)
