# Astro25 File Anatomy

Current high-confidence map of what lives inside the Astro25 `.cpg` files we tested.

Test basis:

- `Just W6SLG.cpg`
- `W6SLG XTS25000 Config.cpg`
- 7 `.cpg` files from `blankcp`

## What The File Actually Is

An Astro25 `.cpg` file is an OLE container with many `DataStg/Strm_*` streams.

Each stream has:

- 2 raw header bytes that identify the record family
- a shared per-file XOR scheme applied by position
- a decrypted payload that holds either text, fixed fields, or repeated table entries

This means the codeplug is not one giant blob. It is a structured database of many small records.

## Layers Inside The File

### 1. Identity / metadata layer

These records identify the radio and codeplug build:

- `9b3e`: model / radio identity strings
- `9b3c`: codeplug serial
- `8b7d`: version / CPS build-style text

Confidence: high in the older samples, mixed in noisier newer-family samples.

### 2. Master directory layer

- `9b3f` in `Strm_0` is the master directory/index

This is one of the most important records in the whole file because it links SIDs to:

- CRCs
- active marker types
- extra per-record values such as encoded frequency or CTCSS tone index

High-confidence finding:

- the `extra` field in `Strm_0` is the most trustworthy source for per-channel CTCSS assignment

### 3. Channel personality / RF parameter layer

These records describe how a channel behaves at the radio level:

- `84c1`: personality / channel template
- `848e`: tone definition block
- `8494`: tone auxiliary block
- `84cd`, `84cf`, `84f0`, `8495`, `8489`: channel config variants

What we can reliably pull today:

- RX frequency from `84c1`
- best-effort TX frequency from band rules
- whether CTCSS is enabled
- RX/TX tone indices from `848e`
- several frequency-like config words from the `84cd` family

Important caveat:

- multi-channel files can contain stale SID references inside some config records, so those cross-links are not always authoritative

### 4. Visible channel / zone label layer

These are the records the user sees most directly:

- `84c5`: visible zone/channel label tables

This family is real, but not universal in one layout. We now know multiple variants:

- single 17-byte label
- single 15-byte label
- 16 x 15-byte table
- 15 x 17-byte table with a separate zone-title/header segment
- several noisier newer-family variants

High-confidence result:

- the W6SLG multizone file and the `M28KSS...` file both contain real visible zone/channel tables in `84c5`
- the W6SLG-style multizone table is now structurally separated into:
  - zone title at bytes `10..26`
  - 15 visible 17-byte slots starting at byte `27`
- the compact `M28KSS...` style table is now structurally separated into:
  - 16 visible 15-byte slots starting at byte `10`
- some `84c5` slots are mixed text/control, not pure ASCII:
  - in the compact M28 family, repeated non-ASCII bytes recur at the same slot-relative positions across every zone table
  - this means at least part of the old “corrupted label” problem is real embedded structure inside specific slots, not just bad display code

### 5. Zone companion / linkage layer

These records sit next to the visible label tables and tell us how the zone structures are organized:

- `84c4`: label companion record
- `84c6`: `84c7` mapping companion record

High-confidence result in the older families:

- `84c4` tracks `84c5` zone tables
- `84c4` word 3 matches the visible label width
- `84c4` word 7 matches the `84c5` record index
- `84c6` tracks the matching `84c7` records for each zone
- `84c6` word 7 gives the base `84c7` record index for that zone

This is a major improvement because zone-to-`84c7` pairing is now confirmed instead of guessed for the older families.

### 6. Zone composite / per-slot parameter layer

- `84c7`: repeated-entry composite records

This is one of the key remaining reverse-engineering targets.

What is now high-confidence:

- several families use a fixed header plus repeated 35-byte entries
- older/multizone families commonly use 12-byte headers for the larger records
- the legacy single-zone family uses a related shorter variant
- entries contain a stable first word and second word
- the first word can act as either:
  - a stream reference
  - an encoded frequency-like value
- the second word acts like a selector / mode / sub-type field

What is not fully solved:

- exact semantics of every word/byte inside the 35-byte entry
- exact slot-to-entry mapping inside a paired zone

### 7. Group / membership layer

- `8b21`: channel group config
- `84f7`: scan/member entries

High-confidence result:

- `8b21` contains tagged references into other records, especially personalities and scan/member entries

This means the codeplug stores group membership / composition separately from just visible labels.

### 8. Global text / menu text layer

- `8b61`: message text table
- `8b63`: status text table

High-confidence result:

- these are not channel records
- older-family files decode as mostly fixed-width 16-slot text tables
- they store radio menu/status alias text such as `MESSAGE 1..16` and `STATUS 1..16`

This matters because it proves the file contains both RF/channel programming and user-facing UI text.

### 9. Optional family-specific zone table layer

- `849b`: optional zone/personality table

High-confidence result:

- `849b` exists in the W6SLG pair
- `849b` is absent from all 7 tested `blankcp` `.cpg` files

So `849b` is real, but optional. It is not a universal requirement of Astro25 `.cpg` files.

## What We Can Say About The Two W6SLG Files

### Just W6SLG.cpg

This is a compact legacy single-zone codeplug containing:

- radio identity metadata
- one visible channel label
- one `84c7` companion record
- one tone block with confirmed `94.8 Hz` RX/TX CTCSS
- 14 personality records / variants
- global message and status text tables

Practical interpretation:

- it is not just “one channel”
- it carries one visible programmed channel, plus multiple supporting templates, config variants, and radio text tables

### W6SLG XTS25000 Config.cpg

This is a multizone codeplug containing:

- the same overall metadata and directory layer
- 3 visible `84c5` zone tables
- 3 confirmed `84c6` zone-to-`84c7` pairings
- 6 `84c7` composite records
- many more personalities, scan/group structures, and support records
- global message and status text tables
- optional `849b` zone/personality records

Practical interpretation:

- this file is a real structured radio configuration database
- it stores visible channels, zone layout, channel/personality support records, menu/status text, tones, and scan/group information

## What Is Still Not Fully Solved

### High confidence, still incomplete

- exact per-slot binding from `84c5` visible labels to the internal `84c7` parameter entries
- exact byte-level semantics of every `84c7` field
- full `849b` meaning in the W6SLG family

### Medium confidence / newer-family problem area

- the `M20KTS...` family clearly uses related ideas, but several words and text layouts differ enough that we should not force the older-family rules onto it yet
- in that family, only the first 8 `84c5` text tables are backed by `84c4` / `84c6` companions, so only those are currently safe to call zone-like tables
- the later `84c5` records in that sample are better treated as auxiliary text/menu tables until their linkage is proven

### Text corruption question

Some “bad text” is likely genuine format variation, and some may be decryption/key-population artifacts at certain offsets. We are no longer normalizing those labels, because that hides the raw evidence needed for principled decoding. At this point, the remaining noisy text should be treated as an unsolved encoding/layout problem rather than a presentation problem.

## Bottom Line

These files are not opaque blobs. At this point we can say with confidence that an Astro25 `.cpg` contains:

- radio/build identity records
- a master stream directory
- channel personalities and tone definitions
- visible zone/channel label tables
- zone companion/linkage records
- per-zone composite parameter records
- group/scan membership records
- global message/status text tables
- optional family-specific zone/personality tables

What remains is mostly the last 20% of the hard part:

- proving exact record-to-slot linkage
- solving the newer-family variants
- getting the format to write-safe round-trip quality
