# FieldHT App Store Screenshots

This repository contains the FieldHT App Store screenshot generator and the exported screenshot sets prepared for App Store Connect.

The generator lives in:

- [appstore-screenshots](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots)

The exported PNG sets are organized by Apple display class:

- [6.9" Display](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots/exports/6.9%22%20Display)
- [6.5" Display](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots/exports/6.5%22%20Display)
- [6.3" Display](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots/exports/6.3%22%20Display)
- [6.1" Display](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots/exports/6.1%22%20Display)

## What Is Included

- custom Next.js screenshot composition app
- source captures used in the layouts
- finished App Store PNG exports
- GPLv3 license

## Generator

Main implementation files:

- [page.tsx](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots/src/app/page.tsx)
- [layout.tsx](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots/src/app/layout.tsx)
- [globals.css](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots/src/app/globals.css)

Run locally:

```bash
cd appstore-screenshots
pnpm install
pnpm dev
```

Build locally:

```bash
cd appstore-screenshots
pnpm build
```

## License

This repository is licensed under GPLv3. See [LICENSE](/Users/benjaminfaershtein/Documents/New%20project/LICENSE).
