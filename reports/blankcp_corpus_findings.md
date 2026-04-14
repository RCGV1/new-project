# BlankCP Corpus Findings

Comparative analysis across the seven `.cpg` files cloned from `blankcp`.

## Main Takeaways

1. We are not looking at one single layout family.
2. `849b` is not universal.
3. `84c5` has multiple label-table variants.
4. `84c7` has multiple structural variants, but the 35-byte entry pattern is real across several files.
5. `84c4` and `84c6` are real zone companion records, and in the older families `84c6` confirms which `84c7` pair belongs to each visible zone table.
6. `8b61` and `8b63` are global message/status text tables, not channel records.

## Tested Files

| File | Streams | Variant Class | `84c5` Lengths | `84c7` Lengths | `849b` Present |
|---|---:|---|---|---|---|
| `H18KEC9PW5AN_180001-001002-5.cpg` | 89 | `legacy_single_zone` | `29` | `46` | No |
| `H18KEF9PW6AN_100004-000002-2.cpg` | 139 | `legacy_single_zone` | `29` | `46` | No |
| `H18UCF9PW6AN_500008-000482-8.cpg` | 143 | `legacy_single_zone` | `29` | `46` | No |
| `H66KDD9PW5BN_500008-000488-2.cpg` | 133 | `legacy_single_zone` | `29` | `46` | No |
| `M21URM9PW1AN_500008-000480-0.cpg` | 170 | `unknown` | `27` | `46` | No |
| `M28KSS9PW1AN _508048-00148C-0.cpg` | 300 | `multizone_compact_labels` | `252` | `222`, `362` | No |
| `M20KTS9PW1AN_100008-000480-9.cpg` | 300 | `extended_labels_or_newer_family` | `27`, `57`, `237`, `252`, `267`, `282`, `312` | `47`, `117`, `187`, `222`, `257`, `292`, `362` | No |

## `84c5` Findings

### Confirmed Variant Shapes

| Decrypted Length | Payload | Best Current Interpretation |
|---:|---:|---|
| `29` | `27` | single 17-byte label |
| `27` | `25` | single 15-byte label |
| `252` | `250` | 16 slots x 15 bytes |
| `284` | `282` | zone title/header at byte `10`, then 15 slots x 17 bytes starting at byte `27` |

### Strong But Not Yet Universal

| Decrypted Length | Payload | Best Current Interpretation | Confidence |
|---:|---:|---|---|
| `312` | `310` | likely 15 slots x 20 bytes | Medium |
| `282` | `280` | likely 15 slots x 18 bytes | Medium |
| `267` | `265` | likely 15 slots x 17 bytes | Medium |
| `237` | `235` | likely 15 slots x 15 bytes | Medium |
| `57` | `55` | likely 3 slots x 15 bytes | Low |

### Important Correction

Earlier reverse-engineering around the two W6SLG files made `84c5` look like one specific layout. The corpus shows that `84c5` is a family of related text-table records, not one fixed schema.

### Embedded Control Bytes Inside `84c5`

The compact M28 family now shows a repeatable mixed-text pattern instead of random corruption:

- slot 3 carries a non-ASCII byte at relative offset `9` in every zone table
- slot 8 carries a non-ASCII byte at relative offset `1` in every zone table
- slot 10 carries non-ASCII bytes at relative offsets `6` and `14` in every zone table
- slot 12 carries a non-ASCII byte at relative offset `10` in every zone table
- slot 15 carries a non-ASCII byte at relative offset `1` in every zone table

This is strong evidence that at least part of the visible-label corruption is caused by embedded control/flag bytes inside specific `84c5` slots, not by a simple ASCII decoding mistake.

## `84c7` Findings

### Confirmed Variant Shapes

| Decrypted Length | Best Current Interpretation |
|---:|---|
| `46` | 11-byte header + 1 x 35-byte entry |
| `222` | 12-byte header + 6 x 35-byte entries |
| `362` | 12-byte header + 10 x 35-byte entries |

### Additional Seen Shapes

| Decrypted Length | Entry Count If Using 35-Byte Blocks | Confidence |
|---:|---:|---|
| `47` | not yet cleanly classified | Low |
| `117` | 3 entries | Medium |
| `187` | 5 entries | Medium |
| `257` | 7 entries | Medium |
| `292` | 8 entries | Medium |

### Structural Notes

- In the W6SLG multizone sample and many blankcp samples, `84c7` behaves like:
  - fixed header
  - repeated 35-byte entries
- The first two bytes of an entry often act as either:
  - a stream reference
  - a frequency-like special value
- The next two bytes are often a selector-like field:
  - `0x642a` in the W6SLG multizone sample
  - `0x320f`, `0x640a`, `0x0100`, `0x0300`, etc. in other families

This means `84c7` is structurally real, but its field semantics differ across families.

## `84c4` / `84c6` Findings

These two headers used to be just “unknown records that scale with zone count.” Comparative testing across the W6SLG pair plus the `M28KSS...` corpus file makes their role much clearer.

### `84c4`

`84c4` count tracks the number of visible `84c5` label tables in all the tested older families.

Strong recurring fields:

| Family | Example `84c4` words | Best Current Interpretation |
|---|---|---|
| W6SLG multizone | `[rec, 2, 1, 17, 255, 20, 4095, rec, crc]` | word 3 matches the 17-byte `84c5` slot width; word 7 matches the `84c5` record index |
| M28 compact multizone | `[rec, 0, 1, 15, 239, 20, 4095, rec, crc]` | word 3 matches the 15-byte `84c5` slot width; word 7 matches the `84c5` record index |
| Legacy single-zone | `[0, 2, 1, 17, 254/255, 20, 4095, 0, crc]` | same shape as the W6SLG family, but only one record |

Best current conclusion:

- `84c4` is a per-zone companion to `84c5`
- `84c4` word 3 is a confirmed label-width marker in the tested older families
- `84c4` word 7 is a confirmed `84c5` record index in the tested older families

### `84c6`

`84c6` also scales with zone count and sits next to the `84c7` family in every tested file.

Strong recurring fields:

| Family | Example `84c6` words | Best Current Interpretation |
|---|---|---|
| W6SLG multizone | `[rec, 29, 1, 35, 255, 10, 4093, 2*rec, 0, crc]` | word 3 matches the `84c7` entry size; word 7 points to the first `84c7` record for that zone |
| M28 compact multizone | `[rec, 31, 1, 35, 239, 10, 4093, 2*rec, 0, crc]` | same confirmed zone-to-`84c7` mapping; word 1 implies 16 visible slots |
| Legacy single-zone | `[0, 29, 1, 35, 254/255, 10, 4093, 0, ..., crc]` | same family shape, but only one `84c7` record exists |

Best current conclusion:

- `84c6` is a per-zone mapping companion to `84c7`
- `84c6` word 3 is a confirmed `84c7` entry-width marker in the tested older families
- `84c6` word 7 is a confirmed `84c7` base record index in the tested older families
- this lets us pair `84c5` zones to `84c7` records using a real pointer instead of the older `record_index // 2` heuristic

### Practical Effect

The parser can now do confirmed zone-to-`84c7` pairing for:

- `Just W6SLG.cpg`
- `W6SLG XTS25000 Config.cpg`
- all four blankcp `legacy_single_zone` samples
- `M28KSS9PW1AN _508048-00148C-0.cpg`

The newer `M20KTS...` family still falls back to heuristic pairing because its `84c4`/`84c6` words do not decode to the older pattern.

Important newer-family correction:

- `M20KTS9PW1AN_100008-000480-9.cpg` contains 16 `84c5` text tables
- only the first 8 of those tables have matching `84c4` and `84c6` companions
- this means only those first 8 tables are currently defensible as zone-like tables
- the later `84c5` tables should be treated as unpaired text/menu tables until proven otherwise

## `849b` Finding

`849b` appears in the W6SLG pair but in none of the seven `blankcp` `.cpg` files.

Conclusion:

- `849b` is not a required top-level Astro25 structure
- any logic that depends on `849b` must be optional

## `8b61` / `8b63` Findings

These records are much more stable than the longer `84c5` channel-label variants.

Best current interpretation:

- `8b61` is a message text table
- `8b63` is a status text table
- older families store them as mostly fixed-width text slots, usually best decoded as 16 slots at 17 bytes starting near offset 12

Examples:

| File | Header | Best Current Decode |
|---|---|---|
| `H18KEF9PW6AN_100004-000002-2.cpg` | `8b61` | `MESSAGE 1` through `MESSAGE 16` with minor corruption in a few labels |
| `H18KEF9PW6AN_100004-000002-2.cpg` | `8b63` | `STATUS 1` through `STATUS 16` with minor corruption in a few labels |
| `Just W6SLG.cpg` | `8b61` | same 16-slot message table family, but a few entries are noisier |
| `Just W6SLG.cpg` | `8b63` | same 16-slot status table family, but a few entries are noisier |
| `M28KSS9PW1AN _508048-00148C-0.cpg` | `8b61` / `8b63` | short single-slot variants (`MSG 1`, `STS 1`) |
| `M20KTS9PW1AN_100008-000480-9.cpg` | `8b61` / `8b63` | same general idea, but the newer-family text is much noisier and not yet cleanly decoded |

This confirms that the codeplug stores more than channels/zones:

- channel-facing tables
- radio/global menu text tables
- status/message alias tables

## Family Separation

The corpus strongly suggests at least three layout families:

### 1. Legacy single-zone family

Examples:

- `H18KEC9PW5AN_180001-001002-5.cpg`
- `H18KEF9PW6AN_100004-000002-2.cpg`
- `H18UCF9PW6AN_500008-000482-8.cpg`
- `H66KDD9PW5BN_500008-000488-2.cpg`

Traits:

- `84c5` length `29`
- `84c7` length `46`
- one visible channel label
- no `849b`

### 2. W6SLG multizone variant

Example:

- `W6SLG XTS25000 Config.cpg`

Traits:

- `84c5` length `284`
- `84c7` lengths `222` and `362`
- visible multizone label tables
- includes `849b`

### 3. Compact multizone labels

Example:

- `M28KSS9PW1AN _508048-00148C-0.cpg`

Traits:

- `84c5` length `252`
- `84c7` lengths `222` and `362`
- 16 visible label slots per table
- no `849b`

### 4. Extended/newer family

Example:

- `M20KTS9PW1AN_100008-000480-9.cpg`

Traits:

- many `84c5` and `84c7` size variants
- text partially decodes but is noisier
- likely a newer or substantially different family
- only the first 8 `84c5` tables are structurally backed by `84c4` / `84c6`
- later `84c5` tables are currently better classified as auxiliary text tables than confirmed zones

## Best New Confirmations

| Finding | Status |
|---|---|
| `84c5` is a family of text-table records with multiple slot-width variants | Confirmed |
| `84c7` has at least one stable repeated-entry pattern using 35-byte entries | Confirmed |
| simple one-channel codeplugs use a distinct `29`/`46` record pairing | Confirmed |
| `849b` is optional, not universal | Confirmed |
| some larger blankcp files belong to a different family than the W6SLG sample | Confirmed |
| in the `M20KTS...` family, not every `84c5` table is a confirmed zone table | Confirmed |

## Remaining Blockers

| Area | Why It Still Matters |
|---|---|
| exact field map of the 35-byte `84c7` entry | needed for authoritative channel parameter decode |
| exact slot-to-parameter mapping inside each paired `84c7` record set | needed for perfect per-channel parameter tables |
| meaning of mixed text/binary bytes in longer `84c5` tables | needed to clean corrupted visible labels |
| family-specific decode logic for the `M20KTS...` sample | needed to separate true zones from auxiliary text/menu tables and avoid over-generalizing the W6SLG rules |
