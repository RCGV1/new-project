# Astro25 Decoded Tables

Current decode snapshot for the two provided `.cpg` files.

Legend:

- `Confirmed`: decoded directly from fields we trust today
- `Inferred`: derived from current reverse-engineering and still subject to change
- `Corrupt text`: visible label bytes contain non-text values we have not mapped yet

## File Summary

| File | Streams | Key Prefix | Model | Codeplug Serial | Version | Tone Block |
|---|---:|---|---|---|---|---|
| `Just W6SLG.cpg` | 129 | `24 de 26 26 de ed d3 1c 5e 45 5e c7` | `H18KEF9PW6AN` | `000001-002000-5` | `11_13_06 ver 4 approved` | `848e` sid `100`, RX/TX `94.8 Hz` |
| `W6SLG XTS25000 Config.cpg` | 207 | `24 de 26 26 de ed d3 1c 5e 44 5e c7` | unknown | candidate `100001-1201` | unknown | `848e` sid `178`, RX/TX `94.8 Hz` |

## Known Channel Config Records

### Just W6SLG.cpg

| Record | SID | Ref A | Ref B | Freq A MHz | Freq B MHz | Status |
|---|---:|---:|---:|---:|---:|---|
| `84cd` | 86 | 101 | 100 | 147.430 | 147.425 | Confirmed |
| `84cf` | 87 | 101 | 20 | 147.420 | 276.000 | Mixed; tail fields still unclear |
| `84f0` | 96 | 101 | 100 | 147.205 | 147.200 | Confirmed |
| `8495` | 102 | 101 | 100 | 147.070 | 147.065 | Confirmed |
| `8489` | 108 | 101 | 100 | 147.090 | 147.085 | Confirmed |

### W6SLG XTS25000 Config.cpg

| Record | SID | Ref A | Ref B | Freq A MHz | Freq B MHz | Status |
|---|---:|---:|---:|---:|---:|---|
| `84cd` | 162 | 50 | 50 | 147.430 | 147.425 | Confirmed; refs appear stale |
| `84cf` | 163 | 50 | 20 | 147.420 | 208.730 | Mixed; tail fields still unclear |
| `84f0` | 174 | 50 | 50 | 147.205 | 147.200 | Confirmed; refs appear stale |
| `8495` | 180 | 50 | 50 | 147.070 | 147.065 | Confirmed; refs appear stale |
| `8489` | 186 | 50 | 50 | 147.090 | 147.085 | Confirmed; refs appear stale |

## Zone And Channel Tables

### Just W6SLG.cpg

Zone source: `84c5` sid `28`

| Zone | Slot | Label | Parsed Freq | Notes | Status |
|---|---:|---|---:|---|---|
| `W6SLG` | 1 | `W6SLG` |  | Single visible channel label | Confirmed |

Linked structures:

| Structure | SID(s) | Notes |
|---|---|---|
| `84c5` | 28 | Zone and visible label |
| `84c7` | 24 | Companion composite record; exact slot mapping still unresolved |
| `848e` | 100 | RX/TX tone `94.8 Hz` |
| `8b21` | 19 | Tagged reference table |
| `8b61` | 41 | 16-slot message text table |
| `8b63` | 38 | 16-slot status text table |

### W6SLG XTS25000 Config.cpg

These zone tables are read from long `84c5` records and should be treated as the best current visible channel list.

#### Zone 1

Zone source: `84c5` sid `33`

| Slot | Visible Label | Parsed Freq MHz | Notes | Status |
|---:|---|---:|---|---|
| 1 | `W6I�C` |  | Corrupt text | Inferred |
| 2 | `J7BE�` |  | Corrupt text | Inferred |
| 3 | `AE6KE` |  |  | Inferred |
| 4 | `W6XLS` |  |  | Inferred |
| 5 | `146.520` | 146.520 |  | Confirmed label, inferred meaning |
| 6 | `146!415` |  | Corrupt text, likely frequency-like | Inferred |
| 7 | `146.430` | 146.430 |  | Confirmed label, inferred meaning |
| 8 | `146.445` | 146.445 |  | Confirmed label, inferred meaning |
| 9 | `146.460` | 146.460 |  | Confirmed label, inferred meaning |
| 10 | `146.585` | 146.585 |  | Confirmed label, inferred meaning |
| 11 | `146.490` | 146.490 |  | Confirmed label, inferred meaning |
| 12 | `146.515` | 146.515 |  | Confirmed label, inferred meaning |
| 13 | `146.535` | 146.535 |  | Confirmed label, inferred meaning |
| 14 | `146.551` | 146.551 |  | Confirmed label, inferred meaning |
| 15 | `APS�` |  | Corrupt text | Inferred |

Linked `84c7` records: `22`, `23`

#### Zone 2

Zone source: `84c5` sid `35`

| Slot | Visible Label | Parsed Freq MHz | Notes | Status |
|---:|---|---:|---|---|
| 1 | `NOB�01` |  | Corrupt text | Inferred |
| 2 | `ONAN�2` |  | Corrupt text | Inferred |
| 3 | `NOAA 3&&&&` |  | NOAA/weather style label with extra padding bytes | Inferred |
| 4 | `NONA 4` |  | Likely `NOAA 4` with text corruption | Inferred |
| 5 | `NOAA 5` |  |  | Inferred |
| 6 | `NOAN 6` |  | Likely `NOAA 6` with text corruption | Inferred |
| 7 | `NOAA 7` |  |  | Inferred |
| 8 | `146.575` | 146.575 |  | Confirmed label, inferred meaning |
| 9 | `147.420` | 147.420 |  | Confirmed label, inferred meaning |
| 10 | `147.5<5` |  | Corrupt text, likely frequency-like | Inferred |
| 11 | `147.450` | 147.450 |  | Confirmed label, inferred meaning |
| 12 | `147.475` | 147.475 |  | Confirmed label, inferred meaning |
| 13 | `146.520` | 146.520 |  | Confirmed label, inferred meaning |
| 14 | `146.521` | 146.521 |  | Confirmed label, inferred meaning |
| 15 | `147�520` |  | Corrupt text, likely frequency-like | Inferred |

Linked `84c7` records: `24`, `25`

#### Zone 3

Zone source: `84c5` sid `37`

| Slot | Visible Label | Parsed Freq MHz | Notes | Status |
|---:|---|---:|---|---|
| 1 | `145�$15/�25` |  | Corrupt text | Inferred |
| 2 | `056!�30/�25` |  | Corrupt text | Inferred |
| 3 | `146.44v5` |  | Corrupt text, frequency-like | Inferred |
| 4 | `149.460 P25` | 149.460 | P25 visible in label | Confirmed label, inferred meaning |
| 5 | `146.475 P25` | 146.475 | P25 visible in label | Confirmed label, inferred meaning |
| 6 | `146!490 P25` |  | Corrupt text, likely frequency-like | Inferred |
| 7 | `146.505 P25` | 146.505 | P25 visible in label | Confirmed label, inferred meaning |
| 8 | `146.520 P25` | 146.520 | P25 visible in label | Confirmed label, inferred meaning |
| 9 | `146.535 P25` | 146.535 | P25 visible in label | Confirmed label, inferred meaning |
| 10 | `146.4:0 P25` |  | Corrupt text, likely frequency-like | Inferred |
| 11 | `146.565 P25` | 146.565 | P25 visible in label | Confirmed label, inferred meaning |
| 12 | `146.590 P25` | 146.590 | P25 visible in label | Confirmed label, inferred meaning |
| 13 | `147.420 P25` | 147.420 | P25 visible in label | Confirmed label, inferred meaning |
| 14 | `147.434 P25` | 147.434 | P25 visible in label | Confirmed label, inferred meaning |
| 15 | `146�450 P25` |  | Corrupt text, likely frequency-like | Inferred |

Linked `84c7` records: `26`, `27`

## Global Message / Status Tables

These are separate from the visible channel-zone tables and appear to back radio menu/status text.

### Just W6SLG.cpg

| Record | SID | Slots | Width | Sample Labels | Status |
|---|---:|---:|---:|---|---|
| `8b61` | 41 | 16 | 17 | `MESSAGE 1`, `MESSAGE 2`, `ME�SAH� 3`, `MESSgac\x064`, `MESSAGE 5` | Confirmed table, mixed text quality |
| `8b63` | 38 | 16 | 17 | `STATUS 1`, `STATUS 2`, `ST�TU\\�3`, `STATsu\x06\x12`, `STATUS 5` | Confirmed table, mixed text quality |

### W6SLG XTS25000 Config.cpg

| Record | SID | Slots | Width | Sample Labels | Status |
|---|---:|---:|---:|---|---|
| `8b61` | 50 | 16 | 17 | `MESSAGE!3`, `N�CSAH� 2`, `MJ�SAH� 3`, `ESSAGE 5` | Confirmed table, noisier text |
| `8b63` | 47 | 16 | 17 | `STATUS 0\x02`, `P�QTU\\�2`, `S[�TU\\�3`, `TATUS 5` | Confirmed table, noisier text |

## `84c7` Entry Tables

These are the current best exact tables for the `84c7` composite records. The structure is now believed to be:

- 12-byte record header
- followed by 35-byte entries
- entry bytes `[0:2]` are either a stream reference or an encoded frequency-like special value
- entry bytes `[2:4]` are a stable selector, usually `0x642a`

### Zone 1 `84c7` Entries

| Record SID | Block | Entry Kind | Entry Target | Selector |
|---:|---:|---|---|---|
| 22 | 0 | stream ref | sid `0` `9b3f` | `0x642a` |
| 22 | 1 | special | freq `147.455 MHz` | `0x642a` |
| 22 | 2 | stream ref | sid `2` `9b3e` | `0x642a` |
| 22 | 3 | stream ref | sid `3` `9b3c` | `0x642a` |
| 22 | 4 | stream ref | sid `4` `8b0e` | `0x642a` |
| 22 | 5 | stream ref | sid `5` `84ca` | `0x642a` |
| 22 | 6 | stream ref | sid `6` `84cb` | `0x642a` |
| 22 | 7 | stream ref | sid `7` `8b22` | `0x642a` |
| 22 | 8 | stream ref | sid `136` `84f7` | `0x0000` |
| 22 | 9 | stream ref | sid `6` `84cb` | `0x0000` |
| 23 | 0 | stream ref | sid `10` `8b70` | `0x642a` |
| 23 | 1 | special | freq `147.405 MHz` | `0x642a` |
| 23 | 2 | stream ref | sid `12` `8b6d` | `0x642a` |
| 23 | 3 | stream ref | sid `13` `8b4a` | `0x642a` |
| 23 | 4 | stream ref | sid `14` `8491` | `0x642a` |
| 23 | 5 | stream ref | sid `15` `8b4b` | `0x642a` |

### Zone 2 `84c7` Entries

| Record SID | Block | Entry Kind | Entry Target | Selector |
|---:|---:|---|---|---|
| 24 | 0 | stream ref | sid `16` `8490` | `0x642a` |
| 24 | 1 | special | freq `147.375 MHz` | `0x642a` |
| 24 | 2 | stream ref | sid `18` `8b31` | `0x642a` |
| 24 | 3 | stream ref | sid `19` `8b72` | `0x642a` |
| 24 | 4 | stream ref | sid `20` `8b30` | `0x642a` |
| 24 | 5 | stream ref | sid `21` `8b36` | `0x642a` |
| 24 | 6 | stream ref | sid `22` `84c7` | `0x642a` |
| 24 | 7 | stream ref | sid `23` `84c7` | `0x642a` |
| 24 | 8 | stream ref | sid `152` `8b1d` | `0x0000` |
| 24 | 9 | stream ref | sid `22` `84c7` | `0x0000` |
| 25 | 0 | stream ref | sid `26` `84c7` | `0x642a` |
| 25 | 1 | special | freq `147.325 MHz` | `0x642a` |
| 25 | 2 | stream ref | sid `28` `84c6` | `0x642a` |
| 25 | 3 | stream ref | sid `29` `84c6` | `0x642a` |
| 25 | 4 | stream ref | sid `30` `84c6` | `0x322f` |
| 25 | 5 | stream ref | sid `31` `8b37` | `0x322f` |

### Zone 3 `84c7` Entries

| Record SID | Block | Entry Kind | Entry Target | Selector |
|---:|---:|---|---|---|
| 26 | 0 | stream ref | sid `32` `84c4` | `0x642a` |
| 26 | 1 | special | freq `147.295 MHz` | `0x642a` |
| 26 | 2 | stream ref | sid `34` `84c4` | `0x642a` |
| 26 | 3 | stream ref | sid `35` `84c5` | `0x642a` |
| 26 | 4 | stream ref | sid `36` `84c4` | `0x642a` |
| 26 | 5 | stream ref | sid `37` `84c5` | `0x642a` |
| 26 | 6 | stream ref | sid `38` `8b6e` | `0x642a` |
| 26 | 7 | stream ref | sid `39` `8b0a` | `0x642a` |
| 26 | 8 | stream ref | sid `168` `84c2` | `0x0000` |
| 26 | 9 | stream ref | sid `38` `8b6e` | `0x0000` |
| 27 | 0 | stream ref | sid `42` `8b0b` | `0x642a` |
| 27 | 1 | special | freq `147.245 MHz` | `0x642a` |
| 27 | 2 | stream ref | sid `44` `8b71` | `0x642a` |
| 27 | 3 | stream ref | sid `45` `84f8` | `0x642a` |
| 27 | 4 | stream ref | sid `46` `8b62` | `0x642a` |
| 27 | 5 | stream ref | sid `47` `8b63` | `0x642a` |

## Current Limitations

| Area | Current State |
|---|---|
| Exact slot-to-`84c7` entry mapping | Not yet proven |
| Multi-channel metadata strings in `9b3e` and `8b7d` | Still partially undecoded |
| Meaning of corrupted bytes inside long `84c5` labels | Unknown |
| Full `849b` zone table semantics | Unknown |
| Safe write-back support | Not ready |
