# FieldHT

FieldHT is an iPhone app for controlling and configuring supported radios over Bluetooth.

The product focus includes:

- live radio control
- quick radio connection and reconnection
- channel and memory group setup
- programmable button and audio configuration
- satellite pass tracking and radio plan visibility

This repository currently contains FieldHT App Store marketing assets and the internal generator used to produce them.

Included here:

- exported App Store screenshots for current iPhone display classes
- source screenshots captured from the app
- a small Next.js composition tool used to generate the store images

The internal asset generator lives in:

- [appstore-screenshots](/Users/benjaminfaershtein/Documents/New%20project/appstore-screenshots)

If you need to regenerate the store assets:

```bash
cd appstore-screenshots
pnpm install
pnpm dev
```

This repository is licensed under GPLv3. See [LICENSE](/Users/benjaminfaershtein/Documents/New%20project/LICENSE).
