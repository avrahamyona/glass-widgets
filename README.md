# GlassWidgets

Original desktop cards for Windows 10 (1809+) and Windows 11. Hebrew RTL UI, Inter and Heebo fonts under SIL OFL. No Apple logos or bundled Apple artwork. Not affiliated with Apple.

## 0.3.1

- One regular Apple Account data login for Notes, Reminders and Calendar (experimental and read-only). CalDAV is an optional separate advanced login. Chrome and official web app cookies remain separate.
- Full MFA flow instead of paused authentication. Explicit code request with delivery status, a user-requested retry with a 60-second cooldown, and a checkbox for codes generated on a trusted device. A request accepted by Apple is not proof of delivery. Security-key and unavailable delivery routes are reported instead of guessed.
- Show widgets now brings enabled cards above other windows without changing the always-on-top preference.

## 0.3.0

- Square and rectangle choices for every card, saved per widget.
- Positions are saved on movement, close and app exit; off-screen cards are moved back to a visible display after monitor changes. Enable Start with Windows in settings to show them after reboot.
- Original dark Stocks-style watchlist with price, daily change and recent-price sparkline. Square shows the first symbol; rectangle shows the first two. Prices come from Yahoo and may be delayed. This is not Apple's Stocks data or iCloud watchlist sync. Portfolio quantities remain saved in settings.
- Compiled .NET 8 Windows media bridge instead of the PowerShell media reader. Sends media commands via standard input, reports rejected commands, retries artwork when the player publishes it late, selects active media sessions. Controls and covers depend on what the source player exposes to Windows. Efi Music is not supported. No invented artwork.
- Central settings access to official iCloud web apps, using a persistent isolated browser session. Remote pages have no app preload or Node access.
- Experimental local read-only Notes, modern Reminders and Calendar data adapter, using a pinned MIT-licensed pyicloud dependency. Manual refresh only with a 60-second cooldown. Requires a separate regular Apple web credential and, when requested, a one-time device code. No create/edit/delete operations. Session state and cached data are encrypted by Windows. Live account support is unverified. Prior local notes remain in notes.json; they are not uploaded or deleted.
- Optional advanced CalDAV uses a separate app-specific password, encrypted by Windows. XML and iCalendar parsing handle namespaces and calendar time zones. Better error reporting and timeouts. Root-cause of the reported user's login failure remains unconfirmed without a live successful account test.
- Top-left links on Notes, Calendar and Reminders open the correct iCloud section in Chrome when installed (default browser fallback otherwise). Chrome must have its own iCloud login; app cookies are never exported into Chrome.

## Install or upgrade

Quit GlassWidgets using its tray menu > Exit before installing the new setup. Install over the existing installed version. Data is not deleted. For an old portable build, stop using the old EXE and shortcut after installation. Unsigned installers may trigger Windows SmartScreen.

## iCloud

Use the experimental single-account data login in Settings to read into the custom cards. The ordinary Apple password is used for login but is not saved. Saved session state can expire; sign in again when requested. For a supported fallback, use Settings > iCloud > Open and sign in for the official web apps. Sign in on Apple's own page and choose its option to stay signed in when offered. Session files persist locally, but Apple may require login or trusted-device verification again. Advanced Data Protection can require enabling web access on the Apple device. This app does not bypass that setting.

Calendar uses the same experimental data session. Optional Advanced CalDAV is separate and requires an app-specific password, not the ordinary password. The experimental data login, official website login, and CalDAV credential have separate honest status. A web login alone does not authorize CalDAV. Chrome also keeps its own login. Passwords are encrypted locally, never sent to a project server or committed to GitHub.

## Battery

AirPods levels use Bluetooth advertisements; availability depends on Bluetooth hardware and advertisements. iPhone battery requires a Shortcuts automation reporting to the app's local authenticated endpoint, on the same private network. No Apple Watch battery integration.

## Build

Free tools: Node 22, Electron, electron-builder, .NET 8, Python 3.12 and PyInstaller. The Actions build packages the read-only CloudBridge onedir executable. Its pyicloud dependency is pinned to commit 24880a561c3f86f130c2f70598103fa5bb13f420; third-party license is included alongside the adapter source. Run `npm install`, then `dotnet publish native/MediaBridge/MediaBridge.csproj -c Release -r win-x64 -o native/MediaBridge/publish`, then `npm run dist` on Windows. GitHub Actions builds the installer.

MIT for original code. Bundled fonts: SIL OFL. See dependencies for their licenses. This is a test build: real Windows media controls, live iCloud account access and reboot behavior still need device testing.

## Experimental iCloud limits

The private Notes/Reminders/Calendar APIs are not supported or guaranteed by Apple. Apple may change or block them. Personal use is not a legal guarantee; review Apple's iCloud terms before using the experimental adapter. It does not accept new service terms automatically, bypass device approval, read locked-note content by force, or change security settings. No promise of full content coverage or write-back.
