# XTS5000 Write Path Findings

## Scope

This report captures the first high-confidence CPS-authored write diff for the W6SLG/XTS5000 family:

- original file:
  [W6SLG XTS25000 Config.cpg](/Users/benjaminfaershtein/Library/Application%20Support/Claude/local-agent-mode-sessions/f305f19d-5c6c-4d61-8cd4-05c15baba217/a7cd1779-ce11-4565-ba97-56928daedd31/local_a9e60ecf-d4d1-4ff3-9708-ae661053b9a0/uploads/W6SLG%20XTS25000%20Config.cpg)
- CPS-saved edited file:
  [W6SLG XTS25000 Config.modified-label-aapc (1).cpg](/Users/benjaminfaershtein/Downloads/W6SLG%20XTS25000%20Config.modified-label-aapc%20%281%29.cpg)

User-reported change intent:

- zone 1 channel renamed to `Codex`
- RX `146.600`
- TX `142.200`
- transmit PL `146.2`

## Changed Streams

Comparing decrypted streams against the original, CPS changed exactly 4 streams:

| SID | Header | Meaning | Change summary |
|---|---|---|---|
| `0` | `9b3f` | directory | mirrored CRC/tail updates |
| `22` | `84c7` | zone 1 parameter row | channel parameter edit |
| `33` | `84c5` | zone 1 visible label table | channel name edit |
| `206` | `8b7d` | version/build metadata | CPS save/version bump |

This is the cleanest confirmed write set so far for a real accepted CPS save.

## `84c5` Write Behavior

`84c5` sid `33` changed the first visible slot label:

| Offset | Original | New |
|---|---|---|
| `27..31` | `W6JWS` | `Codex` |

The same stream also received a new final tail word:

| Field | Original | New |
|---|---|---|
| `84c5` sid `33` tail | `0x6acb` | `0xbffd` |

The older trial edit to slot 15 proved that `84c5` can sometimes be modified without changing its tail if the replacement text happens to collide under the checksum model. CPS did not do that here; it recomputed the stream tail normally.

## `84c7` Write Behavior

The actual channel parameter edit landed in `84c7` sid `22`, block `1`.

Only the frequency value triplet and the final stream tail changed in that row:

### Block 1 before

- entry index `1`
- selector `0x642a`
- values:
  - `a = 0x01bdffc8 = 146.145`
  - `b = 0x01bfd488 = 146.745`
  - `c = 0x01bfd488 = 146.745`
- flags: `0b 00 0b`

### Block 1 after CPS save

- entry index `1`
- selector `0x642a`
- values:
  - `a = 0x01b1f5c0 = 142.200`
  - `b = 0x01bf6340 = 146.600`
  - `c = 0x01bf6340 = 146.600`
- flags: `0b 00 0b`

### Proven interpretation

This CPS save gives the first high-confidence role map for `a_plus_pair` `84c7` entries in this family:

- `value_a` = likely TX frequency
- `value_b` = likely RX frequency
- `value_c` = likely RX mirror / paired copy

That matches both:

- the user-reported edit (`TX 142.2`, `RX 146.6`)
- the pre-existing NOAA-style rows, where `a` already looked like the transmit-side ham frequency and `b/c` looked like the receive-side weather frequency

So for W6SLG/XTS-style `84c7` rows:

- `uniform` rows are likely simplex shared RX/TX
- `a_plus_pair` rows are likely `TX + RX/RX`

## Adjacent Side Effect

CPS also changed two flag bytes in `84c7` sid `22`, block `2`:

| Block | Byte offsets inside block | Original | New |
|---|---|---|---|
| `2` | `22`, `24` | `0b`, `0b` | `18`, `18` |

The frequency triplet in block 2 did not change.

This is important because it means a valid channel edit may require more than:

1. patch visible label in `84c5`
2. patch one `84c7` frequency triplet
3. recompute tails

There is at least one adjacent semantic/control update still not fully explained.

## Stream Tail / Directory Behavior

The CPS save also updated the integrity mirrors exactly where expected:

| Stream | Original tail | New tail |
|---|---:|---:|
| `84c7` sid `22` | `0xe41d` | `0xf98c` |
| `84c5` sid `33` | `0x6acb` | `0xbffd` |

`9b3f` changed in the corresponding directory CRC slots:

- sid `22` directory CRC mirrored `0xf98c`
- sid `33` directory CRC stored `0xbefd`, which is `0xbffd XOR 0x0100`

This reinforces the current writer model:

- recompute the edited stream tail
- mirror that tail into `Strm_0`
- for the first long W6SLG `84c5` directory row, apply the observed `XOR 0x0100` transform

## `8b7d` Save Metadata

`8b7d` sid `206` also changed:

- bytes `4..8`, now understood as a BCD `YY MM DD HH MM` save timestamp
- final tail word, which fits `CRC16-CCITT(decrypted[4:-2])`

This is save metadata rather than channel programming proper, but it now matters for exact CPS-parity reproduction.

## What This Means For Writing

For this XTS5000 family, a real accepted CPS-authored channel edit now looks like:

1. Update visible zone/channel text in `84c5`
2. Update the matching `84c7` block frequency values
3. Recompute the edited stream tails
4. Update `8b7d` save metadata and recompute its tail
5. Mirror the new tails into `9b3f`, including the observed `84c5` XOR quirk
6. Possibly update adjacent `84c7` control bytes

## Remaining Unknowns

These are the main blockers before a reliable writer can claim parity with CPS:

- exact meaning of the adjacent `84c7` block-2 flag change (`0b -> 18`)
- authoritative transmit-PL field mapping for the reported `146.2`
- whether additional records change for more complex edits like zone moves, scan changes, digital personalities, or adding/removing channels

## Bottom Line

This CPS save gave a real write-path breakthrough:

- `84c5` is confirmed as the visible name layer
- `84c7` is confirmed as the live frequency layer for this family
- `a_plus_pair` `84c7` rows now have a practical RX/TX field interpretation
- `9b3f` mirrors the recomputed tails exactly as expected

The writer model is still incomplete, but it is now grounded in a real accepted CPS-authored channel edit rather than inference alone.
