# App Store Screenshots

This project generates App Store marketing screenshots for FieldHT using a custom Next.js composition page and `html-to-image`.

The current set is built from captured iPhone screenshots and exports polished PNGs for these App Store display classes:

- `6.9" Display`
- `6.5" Display`
- `6.3" Display`
- `6.1" Display`

## What It Produces

The current export set contains five slides:

- radio control
- device connection
- channel setup
- settings and programmable buttons
- satellite tracking

Generated files are written under:

- [exports](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots/exports)

Each display folder contains upload-ready PNGs with no alpha channel.

## Source Layout

- [page.tsx](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots/src/app/page.tsx): screenshot layout, slide copy, export sizing, and export logic
- [layout.tsx](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots/src/app/layout.tsx): app shell
- [globals.css](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots/src/app/globals.css): global styling
- `public/screenshots/en/*.png`: captured source screenshots used in the compositions

## Local Development

Install dependencies and run the dev server:

```bash
pnpm install
pnpm dev
```

Then open `http://localhost:3000`.

## Notes

- The current design avoids CSS effects that export poorly, such as `backdrop-filter` on rounded cards.
- Final PNGs are flattened to RGB so App Store Connect does not reject them for alpha transparency.
- The repository root is licensed under GPLv3, so this project is distributed under GPLv3 as well.
