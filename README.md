# Project Workspace

This repository currently contains two active work areas:

- `src/astro25_decoder`: Python utilities for inspecting and editing Motorola Astro 25 `.cpg` codeplug files
- `appstore-screenshots`: a Next.js generator used to build App Store marketing screenshots for the FieldHT iPhone app

The repository is licensed under GPLv3. See [LICENSE](/Users/benjaminfaershtein/Documents/New%20project/LICENSE).

## Astro25 Decoder

The Astro25 tooling can:

- load Astro 25 codeplugs from OLE `DataStg/Strm_*` streams
- derive the per-file XOR key
- decrypt and summarize known record types
- parse `Strm_0` directory entries
- decode personality records, tone blocks, and common metadata
- parse `84c4` / `84c6` zone companion records
- extract `8b61` / `8b63` message and status text tables
- confirm `84c5` zone tables to `84c7` record pairing for older and compact-multizone families
- compare two codeplugs at a high level
- apply best-effort channel edits for the families currently understood well enough to write

### Astro25 Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
astro25 summary "/path/to/file.cpg"
astro25 compare "/path/to/a.cpg" "/path/to/b.cpg"
astro25 write-channel "/path/to/in.cpg" "/path/to/out.cpg" --zone 1 --slot 1 --label TEST
```

### Astro25 Commands

```bash
astro25 summary FILE [--json]
astro25 compare FILE_A FILE_B [--json]
astro25 streams FILE
astro25 analyze FILE [--json]
astro25 inventory FILE [--json]
astro25 write-channel INPUT OUTPUT --zone N --slot N [--label TEXT] [--rx MHZ] [--tx MHZ] [--tx-pl HZ] [--save-time YYYY-MM-DDTHH:MM] [--no-save-metadata] [--json]
```

Current implementation notes:

- [writer_status.md](/Users/benjaminfaershtein/Documents/New%20project/reports/writer_status.md)
- [xts5000_write_path_findings.md](/Users/benjaminfaershtein/Documents/New%20project/reports/xts5000_write_path_findings.md)

## App Store Screenshot Generator

`appstore-screenshots` is a small Next.js app that assembles polished App Store screenshot compositions from captured app screens and exports ready-to-upload PNGs.

Current FieldHT output includes:

- five slides
- four iPhone size classes
- organized exports under `appstore-screenshots/exports`
- RGB PNGs with no alpha channel for App Store Connect compatibility

Primary source files:

- [page.tsx](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots/src/app/page.tsx)
- [layout.tsx](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots/src/app/layout.tsx)
- [globals.css](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots/src/app/globals.css)

The generated image sets are grouped by display class:

- [6.9" Display](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots/exports/6.9%22%20Display)
- [6.5" Display](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots/exports/6.5%22%20Display)
- [6.3" Display](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots/exports/6.3%22%20Display)
- [6.1" Display](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots/exports/6.1%22%20Display)
