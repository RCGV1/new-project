# `84c7` Integrity Findings

## Current Status

This report summarizes what is currently **proven**, **strongly indicated**, and **still unresolved** about:

- `84c7` record structure
- per-stream integrity words
- write-safe update rules

The findings are based on:

- [Just W6SLG.cpg](/Users/benjaminfaershtein/Library/Application%20Support/Claude/local-agent-mode-sessions/f305f19d-5c6c-4d61-8cd4-05c15baba217/a7cd1779-ce11-4565-ba97-56928daedd31/local_a9e60ecf-d4d1-4ff3-9708-ae661053b9a0/uploads/Just%20W6SLG.cpg)
- [W6SLG XTS25000 Config.cpg](/Users/benjaminfaershtein/Library/Application%20Support/Claude/local-agent-mode-sessions/f305f19d-5c6c-4d61-8cd4-05c15baba217/a7cd1779-ce11-4565-ba97-56928daedd31/local_a9e60ecf-d4d1-4ff3-9708-ae661053b9a0/uploads/W6SLG%20XTS25000%20Config.cpg)
- [M28KSS9PW1AN _508048-00148C-0.cpg](/Users/benjaminfaershtein/Documents/New%20project/blankcp/M28KSS9PW1AN%20_508048-00148C-0.cpg)
- [M20KTS9PW1AN_100008-000480-9.cpg](/Users/benjaminfaershtein/Documents/New%20project/blankcp/M20KTS9PW1AN_100008-000480-9.cpg)

## Proven Rules

### 1. `Strm_0` CRC mirrors the decrypted stream tail in stable families

For files where the directory is decoding cleanly, the `Strm_0` entry field currently exposed as `crc` is normally identical to the final 16-bit word of the decrypted stream.

Observed match rates:

| File | Matches | Total |
|---|---:|---:|
| `Just W6SLG.cpg` | 28 | 29 |
| `W6SLG XTS25000 Config.cpg` | 35 | 36 |
| `M28KSS9PW1AN _508048-00148C-0.cpg` | 26 | 32 |
| `M20KTS9PW1AN_100008-000480-9.cpg` | 2 | 8 |

This is the strongest currently proven write-integrity rule in the format.

### 2. The final `84c7` block tail carries the same 16-bit stream integrity word

For `84c7` rows in the stable families, the last 2 bytes of the final block tail match the final 16-bit decrypted stream tail.

Examples:

| File | `84c7` SID | Stream Tail | Final Block Tail Ending |
|---|---:|---:|---:|
| W6SLG XTS | 22 | `0xe41d` | `e4 1d` |
| W6SLG XTS | 23 | `0x3cce` | `3c ce` |
| W6SLG XTS | 24 | `0xcf7c` | `cf 7c` |
| W6SLG XTS | 26 | `0x10a1` | `10 a1` |
| M28 | 37 | `0x8c43` | `8c 43` |
| M28 | 38 | `0x5c61` | `5c 61` |
| M28 | 43 | `0x24ed` | `24 ed` |

### 3. Stable `84c7` rows now have a reconstructible CCITT path

For the stable W6SLG and M28 multizone families, the `84c7` tail is no longer just “some unknown 16-bit word.”

The analyzer now shows that `84c7` rows are compatible with:

- poly `0x1021`
- `refin=False`
- `refout=False`
- input bytes = decrypted stream bytes starting at offset `4`, excluding the final 2-byte tail

In other words:

`tail = CRC16_CCITT_0(decrypted[4:-2]) XOR K_family,length`

Current stable constants:

| Family | `84c7` len | Constant `K_family,length` |
|---|---:|---:|
| W6SLG multizone | `222` | `0x0000` |
| W6SLG multizone | `362` | `0xb152` |
| M28 compact multizone | `222` | `0x2001` |
| M28 compact multizone | `362` | `0x4e74` |

This holds across every `84c7` row currently decoded in those families.

### 4. The broader zone-family records share the same CCITT shape, but with multiple equivalent windows

The integrity analyzer now exposes a `CCITT offset scan` for same-header same-length groups that already have a known-good directory/tail mirror. That scan shows a repeatable pattern:

- byte offsets `2` and `4` often both collapse a family to a single constant
- byte offset `4` is the more semantically stable window for the zone-family records
- the constant changes depending on where the CRC window begins, but the family compatibility remains

The stable zone-family view is now:

`tail = CRC16_CCITT_0(decrypted[start:-2]) XOR K_family,start`

with `start=4` being the most useful write model so far.

Current high-confidence `start=4` results:

| Family | Header | Length | `K` at `start=4` |
|---|---|---:|---:|
| W6SLG multizone | `84c4` | `18` | `0x0000` |
| W6SLG multizone | `84c6` | `21` | `0x0000` |
| W6SLG multizone | `84c7` | `222` | `0x0000` |
| W6SLG multizone | `84c7` | `362` | `0xb152` |
| W6SLG multizone | `84c5` | `284` | `0x0000` |
| W6SLG multizone | `84ca` | `57` | `0x0000` |
| W6SLG multizone | `84cb` | `36` | `0x0000` |
| M28 compact multizone | `84c4` | `18` | `0x377b` |
| M28 compact multizone | `84c6` | `21` | `0x9496` |
| M28 compact multizone | `84c7` | `222` | `0x2001` |
| M28 compact multizone | `84c7` | `362` | `0x4e74` |
| M28 compact multizone | `84ca` | `57` | `0x6b7a` |
| M28 compact multizone | `84cb` | `36` | `0x1bc4` |

Important nuance:

- the analyzer’s raw “best start” often lands on `2` because it picks the earliest uniform window
- for the stable zone families, `start=4` is now explicitly exposed as the preferred semantic window
- W6SLG `84c5` is included here from direct decrypted-body testing even though one record currently has a directory CRC mismatch; the body-level pattern is still uniform

### 5. `84c7` header last word is a family-level tail placeholder hint

The last word of the `84c7` header is not random. In stable families it behaves like a family/template tail marker:

| Family | Common header tail word |
|---|---:|
| W6SLG multizone | `0x0ffb` |
| M28 compact multizone | mostly `0x0fe4`, later paired-frequency rows `0x0ffb` |

This value reappears in non-final block tails.

### 6. `84c7` headers carry pair-link structure, not just length and padding

The stable families now show a repeatable 6-word `84c7` header shape:

| Word | W6SLG long-row example | Meaning status |
|---|---:|---|
| 0 | `0x0000`, `0x0002`, `0x0004` | confirmed record index |
| 1 | `0x016a`, `0x00d6` | family-specific size/span word |
| 2 | `0x0ffd` or `0x0000` | confirmed long-row flag |
| 3 | `0x0001`, `0x0003`, `0x0005` | strongly indicated paired-record link on long rows |
| 4 | `0x000a`, `0x0006` | family-specific span/count word |
| 5 | `0x0ffb` | confirmed tail placeholder |

The pair-link behavior is visible in both stable multizone families:

- W6SLG long rows `0 -> 1`, `2 -> 3`, `4 -> 5`
- M28 long rows `0 -> 1`, `2 -> 3`, `4 -> 5`, `6 -> 7`, `8 -> 9`, `10 -> 11`

### 7. Non-final `84c7` blocks embed placeholder tail patterns, not final integrity words

Stable families reuse family-specific non-final tail shapes:

- W6SLG 222-byte rows: non-final blocks typically end in `01 0f fb`
- W6SLG 362-byte rows: non-final blocks typically end in `00 0f fb` or `01 0f fb`, depending on profile
- M28 222/362-byte rows: non-final blocks commonly end in `0f e4`, `00 e4`, or zero-only variants

This means the last two bytes of the stream are **not** the only integrity-related bytes inside `84c7`; final-block tails also have to be kept coherent.

## `84c7` Structure Status

### W6SLG multizone family

This family is currently the cleanest-decoded `84c7` variant.

- 362-byte rows now decode as `12-byte header + 10 standard blocks`
- 222-byte rows decode as `12-byte header + 6 standard blocks`
- the visible slot order maps cleanly to `84c7` entry order
- all visible channels in the XTS sample now bind to exact `84c7` entries
- long-row headers are now confirmed to link to their paired short rows through header word 3
- the `84c7` integrity word is now compatible with `CRC16-CCITT` over `decrypted[4:-2]`
  - 222-byte rows use constant `0x0000`
  - 362-byte rows use constant `0xb152`

Confirmed visible binding in the XTS file:

- zone 1 -> entries `1..15`
- zone 2 -> entries `17..31`
- zone 3 -> entries `33..47`

### M28 compact multizone family

This family shows the same high-level container ideas:

- 362-byte and 222-byte `84c7` rows
- confirmed `84c6` pairing to visible zones
- two stable header-tail subtypes:
  - early compact rows centered on `0x0fe4`
  - later paired-frequency rows centered on `0x0ffb`
- final block tail ends with the stream tail
- long-row headers also link to the next short-row record through header word 3
- the `84c7` integrity word is also compatible with `CRC16-CCITT` over `decrypted[4:-2]`
  - 222-byte rows use constant `0x2001`
  - 362-byte rows use constant `0x4e74`

But semantic decode is still weaker:

- many blocks still look zero-filled at the current XOR quality
- selector/entry semantics are not yet authoritative
- some rows still classify as partially auxiliary because the body content is not clean enough yet

### M20 newer family

This family is still not globally write-safe, but `84c7` is no longer a total blind spot.

What is now established:

- `84c7` uses many more size variants: `47`, `117`, `187`, `222`, `257`, `292`, `362`
- the dominant `84c7` body class is `362` bytes, and it is internally consistent
- the `84c7` integrity word is compatible with the same non-reflected `0x1021` path over `decrypted[4:-2]`
- the dominant M20 `84c7` constant is:

| Family | `84c7` len | Constant `K_family,length` |
|---|---:|---:|
| M20 newer family | `362` | `0x6c23` |

Additional currently observed M20 `84c7` constants:

| `84c7` len | Count | Constant at `start=4` |
|---|---:|---:|
| `47` | 1 | `0x66ea` |
| `117` | 2 | `0xd0a9` |
| `187` | 1 | `0x8ef1` |
| `222` | 1 | `0x7b36` |
| `257` | 1 | `0xddce` |
| `292` | 1 | `0xf603` |
| `362` | 22 | `0x6c23` |

What is still weak:

- directory CRC mirroring is weak, so the generic integrity summary understates how solved `84c7` is in this family
- only one currently indexed M20 `84c7` row has a parsed directory entry, and it is off by `+1` (`dir - tail = 0x0001`)
- the companion zone records in M20 still do not yet line up with the stable-family write rules cleanly enough for a full writer

## Write-Safe Rules We Can Actually Defend

These are the current minimum rules for a safe writer in the stable families.

### Rule 1. Update the decrypted stream tail word

Any modified stream needs its final 16-bit integrity word recomputed.

### Rule 2. Mirror that same 16-bit word into the `Strm_0` directory entry

The directory `crc` field should match the final decrypted stream tail word.

### Rule 3. For `84c7`, also update the final block tail ending

The final `84c7` block tail must end with the same 16-bit integrity word as the stream tail.

### Rule 4. For stable `84c7`, recompute from the CCITT path instead of only copying

For the currently stable multizone families, the `84c7` integrity word can now be recomputed as:

`CRC16-CCITT(decrypted[4:-2]) XOR K_family,length`

with the constants listed above.

That means stable-family `84c7` writes are no longer blocked on the generic stream-tail mystery.

### Rule 4a. The same `start=4` CCITT model now covers more than `84c7`

For the stable zone families, the current best write model is no longer just “special-case `84c7`.” The same non-reflected `0x1021` path with a family constant also covers:

- W6SLG `84c4`, `84c5`, `84c6`, `84ca`, `84cb`
- M28 `84c4`, `84c6`, `84ca`, `84cb`

So the writer model is starting to look like a family of related rules instead of one isolated checksum hack.

### Rule 5. Preserve family-specific non-final tail templates

For stable families, non-final `84c7` blocks reuse family-level placeholder patterns:

- W6SLG family preserves `...0f fb` placeholders
- M28 family preserves `...0f e4` / `...00 e4` style placeholders

So a writer cannot safely rebuild `84c7` tails by zeroing or copying the final CRC everywhere.

### Rule 6. Preserve `84c7` long-row header linkage

For the stable multizone families, long `84c7` rows are not isolated records. Their headers carry:

- the long-row flag `0x0ffd`
- a paired-record link in header word 3
- family-specific span/size words that differ between long and short rows

So a writer must preserve those header relationships when moving, adding, or deleting `84c7` rows.

## CRC / Checksum Algorithm Status

The exact algorithm that generates the 16-bit integrity word is still unknown.

### What was tested

The decoder now checks common CRC-16 variants against known-good records:

- `ARC`
- `MODBUS`
- `USB`
- `CCITT-FALSE`
- `XMODEM`
- `KERMIT`
- `X25`
- `AUG-CCITT`
- `GENIBUS`
- `DNP`

Tested input forms:

- decrypted body without tail
- raw stream without tail
- raw encrypted body without the 2-byte stream header and without tail
- logical record bytes with the 2-byte stream header reattached
- zero-tail forms of decrypted and logical record inputs
- full raw stream forms

An additional external sweep was also run across 57 published `CRC-16` variants from the `crccheck` catalog.

### Result

No tested common CRC-16 variant matched the stable known-good records.
No tested published `CRC-16` variant from the broader 57-variant catalog matched either.

### New differential result

The decoder now also runs a polynomial-elimination search on the shortest same-length matched record set in each file. This removes unknown `init` / `xorout` effects by comparing only XOR differences between record outputs.

Current outcome:

| File | Selected group | Result |
|---|---|---|
| `M28KSS9PW1AN _508048-00148C-0.cpg` | 7 matched records at len `14` | exactly one survivor: non-reflected `0x1021` on decrypted body without tail |
| `W6SLG XTS25000 Config.cpg` | 7 matched records at len `18` | no surviving polynomial across the full group |

So the format is no longer best described as “CRC completely unknown.” A better description is:

- some stable short-record groups are strongly compatible with a non-reflected `0x1021` CRC over decrypted bytes without the final 16-bit word
- other groups, especially some W6SLG `84c4` / `84c6` / `84c7` paths, still break that simple model

### CCITT compatibility profile

The analyzer now reports a `0x1021` compatibility profile by record length using:

- poly `0x1021`
- `refin=False`
- `refout=False`
- input = decrypted stream without the final 16-bit word

This computes a per-length constant:

`K(length) = tail XOR CRC_0x1021(decrypted_without_tail)`

If all records of the same length share one `K(length)`, that length group is compatible with a fixed-init/xorout CRC model.

High-confidence compatible groups now include:

- W6SLG XTS: lengths `22`, `29`, `30`
- M28: lengths `14`, `18`, `30`

Important incompatible groups under the simple whole-stream window:

- W6SLG XTS: length `18`
- W6SLG XTS: lengths `21`, `222`, `362`
- M28: lengths `36`, `57`

This is especially useful for scoping the remaining problem. The short support/text records are much closer to a solved CRC model than the zone/`84c7` records if you insist on one whole-stream window, but the zone-family records look much healthier once the CRC window is shifted to the structurally meaningful offset.

This means at least one of these is true:

- the integrity word is a nonstandard CRC parameterization
- the CRC is computed over a different byte view for some record families
- the integrity word is not a CRC-16 at all
- some still-unfixed XOR bytes are poisoning the comparison in the weaker families
- `84c7` and some companion records may use additional family-specific finalization rules beyond the short-record CRC path

## What Is Still Missing Before Perfect Writes

1. The exact algorithm for the final 16-bit integrity word.
2. Full confidence on M28 `84c7` semantics.
3. Full confidence on newer-family `84c7` semantics, especially M20.
4. A rule for any secondary integrity fields beyond the mirrored stream tail / directory CRC.

## Additional Evidence

Across the two W6SLG files, identical decrypted record bodies almost always carry the same final 16-bit tail word. The only observed conflicts were two single-byte high-byte drifts:

- `8b22`: `0x18c3` vs `0x19c3`
- `8b10`: `0x4cb0` vs `0x4db0`

One of those (`8b22`) is also a known directory mismatch. So the current evidence still favors a content-derived integrity word, with a small amount of remaining XOR uncertainty rather than a SID-dependent checksum.

Another new clue is that the W6SLG len-18 differential failure is concentrated in the later `84c4` records. The short support records in that same length class cluster together under one `0x1021`-compatible constant, while `84c4` records `rec=1` and `rec=2` diverge. That sharply narrows where the remaining inconsistency is coming from.

The offset-scan work also sharpened the family picture:

- in W6SLG multizone, `84c4`, `84c6`, and `84c7` all become uniform at offset `2`, but offset `4` produces the cleaner zone-family constants, including `0x0000` for `84c4`, `84c6`, and `84c7` short rows
- in M28 compact multizone, `84ca` and `84cb` also become uniform at offset `2`, but offset `4` yields the more stable family constants `0x6b7a` and `0x1bc4`
- this strongly suggests the first 4 decrypted bytes of these zone-family records are structural header material outside the main CRC window

## Bottom Line

What we now know with high confidence:

- `84c7` final block tails are tied to the stream integrity word
- the stream integrity word is mirrored in `Strm_0`
- stable families preserve family-specific non-final tail templates
- W6SLG multizone `84c7` entry ordering is now strong enough to bind every visible channel slot
- the stable zone-family records are broadly compatible with a non-reflected `0x1021` CRC over decrypted bytes beginning at offset `4`, with family-specific constants
- M20 `84c7` itself is also broadly compatible with that same offset-4 `0x1021` model, especially the dominant 362-byte rows with constant `0x6c23`

What we still do **not** know:

- the single generic rule that covers every record family, especially newer-family files and the remaining directory/tail mismatches

So the project is closer to safe writing, but not there yet. The next hard milestone is solving that 16-bit integrity algorithm instead of only locating where it has to be copied.
