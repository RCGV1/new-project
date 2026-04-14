from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from .decoder import load_codeplug
from .writer import write_channel


def _print_summary(summary: dict[str, object]) -> None:
    identity = summary["identity"]
    candidates = summary["metadata_candidates"]
    print(f"File: {summary['path']}")
    print(f"Streams: {summary['stream_count']}")
    print(f"Key prefix: {summary['key_prefix_hex']}")
    print(f"Model: {identity.get('model') or 'unknown'}")
    print(f"Codeplug serial: {identity.get('codeplug_serial') or 'unknown'}")
    print(f"Version: {identity.get('version') or 'unknown'}")
    if not identity.get("model") and candidates["radio_identity"]:
        print(f"Model candidates: {', '.join(candidates['radio_identity'][:3])}")
    if not identity.get("codeplug_serial") and candidates["codeplug_serial"]:
        print(f"Serial candidates: {', '.join(candidates['codeplug_serial'][:3])}")
    if not identity.get("version") and candidates["version"]:
        print(f"Version candidates: {', '.join(candidates['version'][:3])}")

    channel_names = summary["channel_names"]
    global_text_tables = summary["global_text_tables"]
    zone_controls = summary["zone_controls"]
    personalities = summary["personalities"]
    tone_blocks = summary["tone_blocks"]
    directory = summary["directory"]

    print(f"Channel names: {len(channel_names)}")
    for item in channel_names[:10]:
        print(f"  - sid={item['sid']:3d} name={item['name'] or '<blank>'}")
    if len(channel_names) > 10:
        print(f"  ... {len(channel_names) - 10} more")

    print(f"Global text tables: {len(global_text_tables)}")
    for table in global_text_tables[:6]:
        labels = [item["text"] for item in table["labels"][:5]]
        print(
            f"  - sid={table['sid']:3d} type={table['header']} "
            f"slots={table['slot_count'] or 0} width={table['slot_width'] or 0} "
            f"sample={labels}"
        )
    if len(global_text_tables) > 6:
        print(f"  ... {len(global_text_tables) - 6} more")

    print(f"Zone control records: {len(zone_controls)}")
    for row in zone_controls[:8]:
        print(
            f"  - sid={row['sid']:3d} type={row['header']} "
            f"rec={row['record_index']} span={row.get('span_or_count_hint')} "
            f"schema=({row.get('schema_word_a')}, {row.get('schema_word_b')})"
        )
    if len(zone_controls) > 8:
        print(f"  ... {len(zone_controls) - 8} more")

    print(f"Personalities: {len(personalities)}")
    for item in personalities[:10]:
        ctcss = "PL" if item["ctcss_enabled"] else "carrier"
        print(
            f"  - sid={item['sid']:3d} rx={item['rx_mhz']:.3f} tx={item['tx_mhz']:.3f} "
            f"{item['band']} {item['tx_power']} {ctcss}"
        )
    if len(personalities) > 10:
        print(f"  ... {len(personalities) - 10} more")

    print(f"Tone blocks: {len(tone_blocks)}")
    for item in tone_blocks[:10]:
        print(
            f"  - sid={item['sid']:3d} rx={item['rx_hz']}Hz tx={item['tx_hz']}Hz "
            f"counter=0x{item['config_counter']:02x}"
        )
    if len(tone_blocks) > 10:
        print(f"  ... {len(tone_blocks) - 10} more")

    print(f"Directory frequency entries: {len(directory['frequency_entries'])}")
    for item in directory["frequency_entries"][:10]:
        print(
            f"  - entry={item['entry']:3d} sid={item['sid']:3d} "
            f"type={item['header']} value={item['extra']['display']}"
        )
    if len(directory["frequency_entries"]) > 10:
        print(f"  ... {len(directory['frequency_entries']) - 10} more")

    print(f"Directory CTCSS entries: {len(directory['ctcss_entries'])}")
    for item in directory["ctcss_entries"][:10]:
        print(
            f"  - entry={item['entry']:3d} sid={item['sid']:3d} "
            f"type={item['header']} value={item['extra']['display']}"
        )
    if len(directory["ctcss_entries"]) > 10:
        print(f"  ... {len(directory['ctcss_entries']) - 10} more")


def _build_compare(first: dict[str, object], second: dict[str, object]) -> dict[str, object]:
    first_identity = first["identity"]
    second_identity = second["identity"]
    return {
        "first": first["path"],
        "second": second["path"],
        "stream_count_delta": second["stream_count"] - first["stream_count"],
        "identity": {
            "first_model": first_identity.get("model"),
            "second_model": second_identity.get("model"),
            "first_version": first_identity.get("version"),
            "second_version": second_identity.get("version"),
        },
        "counts": {
            "first_channel_names": len(first["channel_names"]),
            "second_channel_names": len(second["channel_names"]),
            "first_personalities": len(first["personalities"]),
            "second_personalities": len(second["personalities"]),
            "first_tone_blocks": len(first["tone_blocks"]),
            "second_tone_blocks": len(second["tone_blocks"]),
            "first_directory_freqs": len(first["directory"]["frequency_entries"]),
            "second_directory_freqs": len(second["directory"]["frequency_entries"]),
            "first_directory_ctcss": len(first["directory"]["ctcss_entries"]),
            "second_directory_ctcss": len(second["directory"]["ctcss_entries"]),
        },
        "key_prefixes": {
            "first": first["key_prefix_hex"],
            "second": second["key_prefix_hex"],
        },
        "stream_types": {
            "first": first["stream_counts"],
            "second": second["stream_counts"],
        },
    }


def _print_analysis(analysis: dict[str, object]) -> None:
    print(f"File: {analysis['path']}")
    variant = analysis["variant"]
    print(
        f"Variant: {variant['family']} "
        f"(84c5 lengths={variant['c5_lengths']}, 84c7 lengths={variant['c7_lengths']}, has_849b={variant['has_849b']})"
    )

    print("Strm_0 directory:")
    for entry in analysis["directory_entries"][:20]:
        print(
            f"  - entry={entry['entry']} rec={entry.get('record_index_word')} "
            f"marker=0x{entry['marker']:04x} sid={entry['sid']} "
            f"type={entry['header']} extra={entry['extra']['display']}"
        )
    extra_dir = len(analysis["directory_entries"]) - 20
    if extra_dir > 0:
        print(f"  ... {extra_dir} more")

    print("Global text tables:")
    for table in analysis["global_text_tables"][:8]:
        labels = [item["text"] for item in table["labels"][:6]]
        print(
            f"  - sid={table['sid']} {table['header']} "
            f"slots={table['slot_count'] or 0} width={table['slot_width'] or 0} "
            f"sample={labels}"
        )
    extra_global = len(analysis["global_text_tables"]) - 8
    if extra_global > 0:
        print(f"  ... {extra_global} more")

    print("Text-bearing records:")
    for row in analysis["text_payload_records"][:16]:
        print(
            f"  - sid={row['sid']} {row['header']} len={row['length']} "
            f"text={row['text_runs'][:3]}"
        )
    extra_text = len(analysis["text_payload_records"]) - 16
    if extra_text > 0:
        print(f"  ... {extra_text} more")

    print("Low-SID support cluster:")
    for row in analysis["support_cluster_records"][:16]:
        details = [
            f"sid={row['sid']}",
            row["header"],
            f"len={row['length']}",
            f"rec={row.get('record_index')}",
        ]
        if "table_length" in row:
            details.append(f"table_offset={row['table_offset']}")
            details.append(f"table_len={row['table_length']}")
            details.append(f"table_kind={row['table_kind']}")
            details.append(f"table={row['table_bytes'][:16]}")
        else:
            if row.get("candidate_sid_refs"):
                details.append(
                    "sid_refs="
                    + ",".join(f"{item['sid']}:{item['header']}" for item in row["candidate_sid_refs"][:4])
                )
            if row.get("candidate_frequency_words"):
                details.append(
                    "freq_words="
                    + ",".join(f"{item['mhz']:.3f}" for item in row["candidate_frequency_words"][:3])
                )
        print("  - " + " ".join(details))
    extra_support = len(analysis["support_cluster_records"]) - 16
    if extra_support > 0:
        print(f"  ... {extra_support} more")

    print("84c5 text tables:")
    for table in analysis["zone_label_tables"][:12]:
        labels = []
        for item in table["labels"][:6]:
            text = item["text"] or "<blank>"
            if item["non_ascii_bytes"]:
                text += f" [mixed:{','.join(str(row['relative_offset']) for row in item['non_ascii_bytes'])}]"
            labels.append(text)
        print(
            f"  - sid={table['sid']} rec={table['record_index']} "
            f"layout={table.get('layout_source')} base={table.get('label_base_offset')} "
            f"slots={table.get('slot_count') or 0} width={table.get('slot_width') or 0} "
            f"zone_label={table.get('zone_label') or '<none>'} sample={labels}"
        )
    extra_tables = len(analysis["zone_label_tables"]) - 12
    if extra_tables > 0:
        print(f"  ... {extra_tables} more")

    print("84c4/84c6 zone companions:")
    for row in analysis["zone_companions"][:20]:
        if row["header"] == "84c4":
            print(
                f"  - sid={row['sid']} 84c4 rec={row['record_index']} "
                f"label_width={row.get('label_width')} c5_record_index={row.get('c5_record_index')} "
                f"flags=0x{row.get('flags_word', 0):04x}"
            )
        else:
            print(
                f"  - sid={row['sid']} 84c6 rec={row['record_index']} "
                f"c7_entry_width={row.get('c7_entry_width')} c7_base_record_index={row.get('c7_base_record_index')} "
                f"visible_slots={row.get('visible_slot_count')} flags=0x{row.get('flags_word', 0):04x}"
            )
    remaining_companions = len(analysis["zone_companions"]) - 20
    if remaining_companions > 0:
        print(f"  ... {remaining_companions} more")

    print("84ca/84cb/849b zone controls:")
    for row in analysis["zone_controls"][:12]:
        if row["header"] == "849b":
            print(
                f"  - sid={row['sid']} 849b rec={row['record_index']} "
                f"profile={row.get('profile_word')} profile_index={row.get('profile_index_hint')} "
                f"span={row.get('span_or_count_hint')}"
            )
        else:
            print(
                f"  - sid={row['sid']} {row['header']} rec={row['record_index']} "
                f"span={row.get('span_or_count_hint')} routing={row.get('routing_words')}"
            )
    extra_controls = len(analysis["zone_controls"]) - 12
    if extra_controls > 0:
        print(f"  ... {extra_controls} more")

    print("84c1 personality variants:")
    for row in analysis["personality_variants"][:12]:
        details = [
            f"variant={row['variant_index']}",
            f"count={row['count']}",
            f"band={row['band']}",
            f"power={row['tx_power']}",
            f"ctcss={'yes' if row['ctcss_enabled'] else 'no'}",
            f"channel_mode={row['channel_mode']}",
            f"squelch={row['squelch']}",
            f"flags=0x{row['mode_flags']:02x}",
        ]
        if row.get("rx_mhz") is not None:
            details.append(f"rx={row['rx_mhz']:.3f}")
        if row.get("tx_mhz") is not None:
            details.append(f"tx={row['tx_mhz']:.3f}")
        details.append(f"records={row['record_indexes'][:8]}")
        print("  - " + " ".join(details))
    extra_variants = len(analysis["personality_variants"]) - 12
    if extra_variants > 0:
        print(f"  ... {extra_variants} more")

    print("Channel config records:")
    for row in analysis["channel_configs"][:12]:
        details = [
            f"sid={row['sid']}",
            row["header"],
            f"rec={row['record_index']}",
            f"members={row.get('member_count')}",
            f"ref_a={row.get('ref_a_sid')}",
        ]
        if row.get("ref_b_sid") is not None:
            details.append(f"ref_b={row.get('ref_b_sid')}")
        if row.get("variant_word") is not None:
            details.append(f"variant=0x{row['variant_word']:04x}")
        if row.get("freq_a_mhz") is not None:
            details.append(f"freq_a={row['freq_a_mhz']:.3f}")
        if row.get("freq_b_mhz") is not None:
            details.append(f"freq_b={row['freq_b_mhz']:.3f}")
        if row.get("pad_word") is not None:
            details.append(f"pad=0x{row['pad_word']:04x}")
        print("  - " + " ".join(details))
    extra_configs = len(analysis["channel_configs"]) - 12
    if extra_configs > 0:
        print(f"  ... {extra_configs} more")

    print("84f7 scan members:")
    for row in analysis["scan_list_members"][:12]:
        details = [
            f"sid={row['sid']}",
            f"rec={row['record_index']}",
            f"active=0x{row['active_code']:02x}",
            f"flags=0x{row['flags']:02x}",
        ]
        if row.get("rx_mhz") is not None:
            details.append(f"rx={row['rx_mhz']:.3f}")
        if row.get("tx_mhz") is not None:
            details.append(f"tx={row['tx_mhz']:.3f}")
        print("  - " + " ".join(details))
    extra_scan = len(analysis["scan_list_members"]) - 12
    if extra_scan > 0:
        print(f"  ... {extra_scan} more")

    print("Unknown headers:")
    for row in analysis["unknown_headers"][:20]:
        print(
            f"  - {row['header']} count={row['count']} sizes={row['sizes']} "
            f"sids={row['sids']}"
        )
    remaining = len(analysis["unknown_headers"]) - 20
    if remaining > 0:
        print(f"  ... {remaining} more")

    print("8b21 tagged refs:")
    for group in analysis["channel_group_refs"]:
        print(
            f"  - sid={group['sid']} len={group['length']} "
            f"pairs={len(group['pairs'])} refs={len(group['tagged_refs'])}"
        )
        for ref in group["tagged_refs"][:24]:
            print(
                f"    off={ref['offset']:03d} tag={ref['tag_hex']} "
                f"sid={ref['sid']:3d} type={ref['header']} kind={ref['kind']} group={ref.get('ref_group', 'other')}"
            )
        extra = len(group["tagged_refs"]) - 24
        if extra > 0:
            print(f"    ... {extra} more")

    print("84c7 segmented blocks:")
    for row in analysis["extended_c7_blocks"]:
        print(
            f"  - sid={row['sid']} len={row['length']} "
            f"blocks={row['block_count']} standard={row['standard_block_count']} "
            f"aux={row['auxiliary_block_count']} header={row['header_length']} trailer={row['trailer_length']} "
            f"header_words={row['header_words_hex']} len_delta={row['header_length_delta_to_stream']}"
            + (
                f" link={row['header_link_word_hex']}"
                if row.get("header_link_word") not in {None, 0}
                else ""
            )
        )
        for block in row["blocks"][:5]:
            if block["entry_ref"]:
                entry_text = f"sid={block['entry_ref']['sid']}"
            elif block.get("entry_index") is not None:
                entry_text = f"entry_index={block['entry_index']}"
                if block.get("ctcss_candidate_hz") is not None:
                    entry_text += f" ctcss?={block['ctcss_candidate_hz']:.1f}"
            elif block["entry_frequency_mhz"] is not None:
                entry_text = f"entry_word_freq={block['entry_frequency_mhz']:.3f}"
            else:
                entry_text = f"code=0x{block['entry_code']:04x}"
            freq_text = ",".join(
                f"{item['field']}={item['mhz']:.3f}"
                + ("*" if item["flag_high_bit"] else "")
                for item in block["frequency_values"]
                if item["mhz"] is not None
            ) or "none"
            print(
                f"    block={block['index']} class={block['block_class']} entry={entry_text} "
                f"selector=0x{block['selector']:04x} values=({block['value_a_hex']},{block['value_b_hex']},{block['value_c_hex']}) "
                f"freqs={freq_text} pattern={block['value_pattern']} flags={block['flag_bytes_hex']}"
                + (f" hint={block['profile_hint']}" if block.get("profile_hint") else "")
                + (
                    f" roles=tx={block['likely_tx_mhz']:.3f},rx={block['likely_rx_mhz']:.3f}"
                    if block.get("likely_tx_mhz") is not None and block.get("likely_rx_mhz") is not None
                    else ""
                )
            )
        extra = len(row["blocks"]) - 5
        if extra > 0:
            print(f"    ... {extra} more blocks")

    print("84c7 tail patterns:")
    for row in analysis["c7_tail_patterns"][:12]:
        nonfinal = ", ".join(
            f"{item['tail_hex']} x{item['count']}"
            for item in row["nonfinal_tail_patterns"][:3]
        ) or "none"
        print(
            f"  - sid={row['sid']} len={row['length']} rec={row['record_index']} "
            f"header_tail={row.get('header_tail_word_hex')} final_tail={row.get('final_stream_tail_word_hex')} "
            f"final_block_tail={row.get('final_block_tail_hex')} nonfinal={nonfinal}"
        )
    extra_c7_tails = len(analysis["c7_tail_patterns"]) - 12
    if extra_c7_tails > 0:
        print(f"  ... {extra_c7_tails} more")

    print("84c7 CCITT profile:")
    for row in analysis["c7_ccitt_profile"]:
        print(
            f"  - len={row['length']} count={row['count']} "
            f"ccitt_offset4_unique={row['unique_length_constants']} "
            f"constants={row['length_constants']}"
        )
        for record in row["records"][:8]:
            print(
                f"    sid={record['sid']} rec={record['record_index']} tail={record['tail_hex']} "
                f"ccitt4={record['ccitt_crc_from_offset_4_hex']} k={record['length_constant_hex']}"
            )
        extra_records = len(row["records"]) - 8
        if extra_records > 0:
            print(f"    ... {extra_records} more")

    print("84c7 CCITT offset scan:")
    for row in analysis["c7_ccitt_offset_scan"]:
        print(
            f"  - len={row['length']} count={row['count']} best_start={row['best_start']} "
            f"preferred_start={row['preferred_start']} best_unique={row['best_unique_constants']} "
            f"best_constants={row['best_constants']} uniform_starts={row['uniform_starts']} "
            f"preferred_constants={row['preferred_constants']}"
        )
        for record in row["records"][:6]:
            print(
                f"    sid={record['sid']} rec={record['record_index']} tail={record['tail_hex']}"
            )
        extra_records = len(row["records"]) - 6
        if extra_records > 0:
            print(f"    ... {extra_records} more")

    print("84c7 directory delta profile:")
    for row in analysis["c7_directory_delta_profile"]:
        print(
            f"  - len={row['length']} count={row['count']} unique_deltas={row['unique_deltas']} "
            f"deltas={row['deltas']}"
        )
        for record in row["records"][:6]:
            print(
                f"    sid={record['sid']} rec={record['record_index']} dir={record['directory_crc_hex']} "
                f"tail={record['tail_hex']} delta={record['delta_hex']}"
            )
        extra_records = len(row["records"]) - 6
        if extra_records > 0:
            print(f"    ... {extra_records} more")

    integrity = analysis["integrity_summary"]
    print("Integrity summary:")
    print(
        f"  - directory_crc_matches_stream_tail={integrity['directory_tail_matches']}/"
        f"{integrity['directory_tail_total']}"
    )
    for row in integrity["mismatches"][:10]:
        print(
            f"  - mismatch sid={row['sid']} type={row['header']} len={row['length']} "
            f"dir={row['directory_crc_hex']} tail={row['stream_tail_hex']}"
        )
    extra_mismatches = len(integrity["mismatches"]) - 10
    if extra_mismatches > 0:
        print(f"  ... {extra_mismatches} more mismatches")
    if integrity["common_crc16_candidates"]:
        print("  common CRC16 candidates:")
        for row in integrity["common_crc16_candidates"][:8]:
            print(
                f"    {row['variant']} on {row['input']} matches "
                f"{row['matches']}/{row['total']}"
            )
    else:
        print("  common CRC16 candidates: none")

    print("CCITT profile:")
    for row in integrity["ccitt_profile"][:12]:
        print(
            f"  - len={row['length']} count={row['count']} "
            f"ccitt_constant_unique={row['unique_length_constants']} "
            f"constants={row['length_constants'][:4]}"
        )
        for record in row["records"][:6]:
            print(
                f"    sid={record['sid']} type={record['header']} tail={record['tail_hex']} "
                f"crc0={record['crc_zero_hex']} k={record['length_constant_hex']}"
            )
    extra_ccitt = len(integrity["ccitt_profile"]) - 12
    if extra_ccitt > 0:
        print(f"  ... {extra_ccitt} more")

    print("CCITT offset scan:")
    for row in integrity["ccitt_offset_scan"][:16]:
        print(
            f"  - type={row['header']} ({row['header_name']}) len={row['length']} "
            f"count={row['count']} best_start={row['best_start']} "
            f"preferred_start={row['preferred_start']} "
            f"best_unique={row['best_unique_constants']} "
            f"constants={row['best_constants']} uniform_starts={row['uniform_starts']} "
            f"preferred_constants={row['preferred_constants']}"
        )
        best_row = None
        for candidate in row["offset_rows"]:
            if candidate["start"] == row["best_start"]:
                best_row = candidate
                break
        if best_row is not None:
            print(
                f"    best_row start={best_row['start']} "
                f"unique={best_row['unique_constants']} constants={best_row['constants']}"
            )
        if row["preferred_start"] != row["best_start"]:
            preferred_row = None
            for candidate in row["offset_rows"]:
                if candidate["start"] == row["preferred_start"]:
                    preferred_row = candidate
                    break
            if preferred_row is not None:
                print(
                    f"    preferred_row start={preferred_row['start']} "
                    f"unique={preferred_row['unique_constants']} constants={preferred_row['constants']}"
                )
    extra_offset_rows = len(integrity["ccitt_offset_scan"]) - 16
    if extra_offset_rows > 0:
        print(f"  ... {extra_offset_rows} more")

    diff = integrity["differential_crc16_search"]
    print("Differential CRC16 search:")
    if diff["selected_length"] is None:
        print("  - no eligible same-length matched record set")
    else:
        print(
            f"  - selected_len={diff['selected_length']} sids={diff['selected_sids']} "
            f"headers={diff['selected_headers']} pairs={diff['pair_count']}"
        )
        for row in diff["results"]:
            progress = ", ".join(
                f"{item['pair'][0]}-{item['pair'][1]}:{item['survivors']}"
                for item in row["pair_progress"][:4]
            )
            print(
                f"    input={row['input']} refin={row['refin']} refout={row['refout']} "
                f"survivors={row['survivor_count']} sample={row['survivor_sample'][:6]}"
                + (f" progress={progress}" if progress else "")
            )


def _print_inventory(inventory: list[dict[str, object]], path: str) -> None:
    print(f"File: {path}")
    for zone in inventory:
        label = "Zone" if zone["classification"] == "zone_table" else "Table"
        print(
            f"{label} {zone['zone_index'] + 1}: {zone['zone_label']} "
            f"(84c5 sid={zone['table_sid']}, 84c7 sids={zone['c7_record_sids']}, "
            f"class={zone['classification']}, pairing={zone['pairing_source']}"
            f"{', c6 sid=' + str(zone['c6_companion_sid']) if zone.get('c6_companion_sid') is not None else ''})"
        )
        if zone.get("slot_width") and zone.get("slot_count"):
            print(
                f"  layout: base={zone.get('label_base_offset')} slots={zone['slot_count']} "
                f"width={zone['slot_width']} source={zone.get('layout_source')}"
            )
        for channel in zone["channels"]:
            if not any(
                [
                    channel["label"],
                    channel["label_frequency_mhz"],
                ]
            ):
                continue
            parts = [f"slot={channel['index'] + 1}"]
            if channel["label"]:
                parts.append(f"label={channel['label']}")
            if channel["label_frequency_mhz"] is not None:
                parts.append(f"label_freq={channel['label_frequency_mhz']:.3f}")
            if channel["non_ascii_bytes"]:
                parts.append(
                    "mixed="
                    + ",".join(
                        f"{row['relative_offset']}=0x{row['value']:02x}"
                        for row in channel["non_ascii_bytes"]
                    )
                )
            if channel.get("c7_matches"):
                parts.append(
                    "c7="
                    + ",".join(
                        f"{row['record_sid']}:{row['block_index']}"
                        + (f"[{''.join(row['matched_fields'])}]" if row["matched_fields"] else "")
                        + (f":{row['profile_hint']}" if row.get("profile_hint") else "")
                        for row in channel["c7_matches"][:3]
                    )
                )
            ordered = channel.get("ordered_c7_entry")
            if ordered is not None:
                parts.append(
                    "c7_order="
                    + f"{ordered['record_sid']}:{ordered['block_index']}"
                    + (f"[{ordered['entry_index']}]" if ordered.get("entry_index") is not None else "")
                    + (f":{ordered['profile_hint']}" if ordered.get("profile_hint") else "")
                )
            print("  - " + " ".join(parts))
        if zone["c7_entries"]:
            print("  c7 entries:")
            for entry in zone["c7_entries"][:12]:
                details = [
                    f"record_sid={entry['record_sid']}",
                    f"record_index={entry['record_index']}",
                    f"block={entry['block_index']}",
                    f"class={entry.get('block_class', 'unknown')}",
                ]
                if entry.get("entry_index") is not None:
                    details.append(f"entry_index={entry['entry_index']}")
                    if entry.get("ctcss_candidate_hz") is not None:
                        details.append(f"ctcss?={entry['ctcss_candidate_hz']:.1f}")
                elif entry["entry_ref"]:
                    details.append(
                        f"entry_sid={entry['entry_ref']['sid']}:{entry['entry_ref']['header']}"
                    )
                elif entry["entry_frequency_mhz"] is not None:
                    details.append(f"entry_freq={entry['entry_frequency_mhz']:.3f}")
                else:
                    details.append(f"entry_code=0x{entry['entry_code']:04x}")
                if entry["selector_frequency_mhz"] is not None:
                    details.append(f"selector_freq={entry['selector_frequency_mhz']:.3f}")
                else:
                    details.append(f"selector=0x{entry['selector']:04x}")
                freq_text = ",".join(
                    f"{item['field']}={item['mhz']:.3f}"
                    + ("*" if item["flag_high_bit"] else "")
                    for item in entry["frequency_values"]
                    if item["mhz"] is not None
                )
                if freq_text:
                    details.append(f"freqs={freq_text}")
                details.append(
                    f"values=({entry['value_a_hex']},{entry['value_b_hex']},{entry['value_c_hex']})"
                )
                details.append(f"pattern={entry['value_pattern']}")
                if entry.get("profile_hint"):
                    details.append(f"hint={entry['profile_hint']}")
                if entry.get("likely_tx_mhz") is not None and entry.get("likely_rx_mhz") is not None:
                    details.append(f"tx={entry['likely_tx_mhz']:.3f}")
                    details.append(f"rx={entry['likely_rx_mhz']:.3f}")
                print("  - " + " ".join(details))
            extra_entries = len(zone["c7_entries"]) - 12
            if extra_entries > 0:
                print(f"  ... {extra_entries} more c7 entries")


def _print_write_report(report: dict[str, object]) -> None:
    print(f"Input: {report['input_path']}")
    print(f"Output: {report['output_path']}")
    print(f"Family: {report['family']}")
    print(f"Edited streams: {report['edited_streams']}")
    print(f"Directory updates: {report['directory_updates']}")
    if report["notes"]:
        print("Notes:")
        for note in report["notes"]:
            print(f"  - {note}")
    if report["warnings"]:
        print("Warnings:")
        for warning in report["warnings"]:
            print(f"  - {warning}")


def _parse_save_time(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "save time must be ISO format like 2026-04-06T16:47"
        ) from exc


def main() -> None:
    parser = argparse.ArgumentParser(prog="astro25")
    subparsers = parser.add_subparsers(dest="command", required=True)

    summary_parser = subparsers.add_parser("summary", help="Summarize a codeplug")
    summary_parser.add_argument("file", type=Path)
    summary_parser.add_argument("--json", action="store_true", dest="as_json")

    compare_parser = subparsers.add_parser("compare", help="Compare two codeplugs")
    compare_parser.add_argument("first", type=Path)
    compare_parser.add_argument("second", type=Path)
    compare_parser.add_argument("--json", action="store_true", dest="as_json")

    streams_parser = subparsers.add_parser("streams", help="List all streams")
    streams_parser.add_argument("file", type=Path)
    streams_parser.add_argument("--json", action="store_true", dest="as_json")

    analyze_parser = subparsers.add_parser("analyze", help="Run deeper reverse-engineering analysis")
    analyze_parser.add_argument("file", type=Path)
    analyze_parser.add_argument("--json", action="store_true", dest="as_json")

    inventory_parser = subparsers.add_parser("inventory", help="Infer zones and channel labels")
    inventory_parser.add_argument("file", type=Path)
    inventory_parser.add_argument("--json", action="store_true", dest="as_json")

    write_parser = subparsers.add_parser("write-channel", help="Write a best-effort channel edit")
    write_parser.add_argument("input", type=Path)
    write_parser.add_argument("output", type=Path)
    write_parser.add_argument("--zone", type=int, required=True)
    write_parser.add_argument("--slot", type=int, required=True)
    write_parser.add_argument("--label")
    write_parser.add_argument("--rx", type=float, dest="rx_mhz")
    write_parser.add_argument("--tx", type=float, dest="tx_mhz")
    write_parser.add_argument("--tx-pl", type=float, dest="tx_pl_hz")
    write_parser.add_argument(
        "--save-time",
        type=_parse_save_time,
        help="Override the 8b7d save timestamp, for example 2026-04-06T16:47",
    )
    write_parser.add_argument(
        "--no-save-metadata",
        action="store_true",
        help="Leave 8b7d save metadata untouched",
    )
    write_parser.add_argument("--json", action="store_true", dest="as_json")

    args = parser.parse_args()

    if args.command == "summary":
        summary = load_codeplug(args.file).summary()
        if args.as_json:
            print(json.dumps(summary, indent=2))
        else:
            _print_summary(summary)
        return

    if args.command == "compare":
        first = load_codeplug(args.first).summary()
        second = load_codeplug(args.second).summary()
        result = _build_compare(first, second)
        if args.as_json:
            print(json.dumps(result, indent=2))
            return
        print(f"First:  {result['first']}")
        print(f"Second: {result['second']}")
        print(f"Stream delta: {result['stream_count_delta']}")
        print(
            f"Models: {result['identity']['first_model'] or 'unknown'} -> "
            f"{result['identity']['second_model'] or 'unknown'}"
        )
        print(
            f"Versions: {result['identity']['first_version'] or 'unknown'} -> "
            f"{result['identity']['second_version'] or 'unknown'}"
        )
        for label, value in result["counts"].items():
            print(f"{label}: {value}")
        print(f"Key prefixes: {result['key_prefixes']['first']} | {result['key_prefixes']['second']}")
        return

    if args.command == "streams":
        codeplug = load_codeplug(args.file)
        streams = [
            {
                "sid": record.sid,
                "header": record.header,
                "header_name": record.header_name,
                "raw_size": record.raw_size,
            }
            for record in codeplug.iter_streams()
        ]
        if args.as_json:
            print(json.dumps(streams, indent=2))
            return
        for item in streams:
            print(
                f"sid={item['sid']:3d} header={item['header']} "
                f"name={item['header_name']} size={item['raw_size']}"
            )
        return

    if args.command == "analyze":
        analysis = load_codeplug(args.file).deep_analysis()
        if args.as_json:
            print(json.dumps(analysis, indent=2))
            return
        _print_analysis(analysis)
        return

    if args.command == "inventory":
        codeplug = load_codeplug(args.file)
        inventory = codeplug.inferred_channel_inventory()
        if args.as_json:
            print(json.dumps({"path": str(args.file), "inventory": inventory}, indent=2))
            return
        _print_inventory(inventory, str(args.file))
        return

    if args.command == "write-channel":
        report = write_channel(
            args.input,
            args.output,
            zone=args.zone,
            slot=args.slot,
            label=args.label,
            rx_mhz=args.rx_mhz,
            tx_mhz=args.tx_mhz,
            tx_pl_hz=args.tx_pl_hz,
            touch_save_metadata=not args.no_save_metadata,
            save_datetime=args.save_time,
        )
        payload = {
            "input_path": report.input_path,
            "output_path": report.output_path,
            "family": report.family,
            "edited_streams": report.edited_streams,
            "directory_updates": report.directory_updates,
            "warnings": report.warnings,
            "notes": report.notes,
        }
        if args.as_json:
            print(json.dumps(payload, indent=2))
            return
        _print_write_report(payload)


if __name__ == "__main__":
    main()
