# GlassWidgets

Desktop widgets for Windows: rounded cards, Inter type, light and dark.

Widgets so far: Clock, Weather, Notes, Clipboard History, System Monitor. Tray icon toggles each one.

Built with Electron. `npm install && npm start` to run, `npm run dist` for a portable .exe. The Windows build also runs in GitHub Actions.

Font: Inter (SIL OFL), see `src/shared/fonts`.

License: MIT for the code (see LICENSE). Inter is under the SIL Open Font License.

## Setup notes

- Calendar: type your Apple ID and an app-specific password (appleid.apple.com, Sign-In and Security) into the widget. It is stored encrypted by Windows and used only for caldav.icloud.com.
- Battery: AirPods levels come from their Bluetooth advertisement (works when the case lid is open or the buds are in use). iPhone level needs a Shortcuts automation that opens the URL from the tray item "Copy iPhone battery URL". Apple Watch level cannot be read.
- Now Playing: shows whatever app Windows reports as the current media session (title, artist, artwork, progress) with play/pause/next/previous.
