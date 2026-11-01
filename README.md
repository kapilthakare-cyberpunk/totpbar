# TOTPBar 🛡️

A lightweight, privacy-focused native macOS menu bar app for Time-Based One-Time Passwords (TOTP / 2FA), built in pure Swift using Apple's **CryptoKit** with zero external dependencies.

[![macOS](https://img.shields.io/badge/macOS-13.0%2B-blue?style=flat-square&logo=apple)](https://www.apple.com/macos)
[![Swift](https://img.shields.io/badge/Swift-5.9%2B%20%7C%206.0-orange?style=flat-square&logo=swift)](https://swift.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-brightgreen?style=flat-square)](#architecture)

---

## Highlights

- ⚡ **Native & Minimalist**: Runs cleanly in the menu bar as an accessory (`LSUIElement` mode). No dock icon, no bloated web-views, sub-millisecond startup.
- 🔒 **Apple CryptoKit**: Uses hardware-accelerated cryptographic primitives for HMAC generation. Full support for **SHA-1** (RFC 6238 standard), **SHA-256**, and **SHA-512**.
- 📋 **Privacy-Preserving Clipboard**:
  - One-click copy formats the current code for immediate use.
  - Registers `org.nspasteboard.ConcealedType` so clipboard history managers (e.g. Maccy, Paste) won't store confidential 2FA codes.
  - Automatically wipes the clipboard after 30 seconds if unchanged.
- ⏱️ **Live Countdown & Warning**: Dynamically displays remaining token lifetime with color-coded alerts (turns red when ≤ 5 seconds remaining).
- 📌 **Pin & Organize**: Option-click (`⌥ + Click`) any account to toggle pinning directly in the root menu bar view. Non-pinned accounts stay grouped in a tidy submenu.
- 📁 **Simple Plain-Text Config**: Reads standard Key URIs (`otpauth://totp/...`) from `~/.config/totp/accounts.txt` with POSIX `0600` permissions.

---

## Quick Start

### Prerequisites
- macOS 13.0 (Ventura) or newer
- Xcode Command Line Tools (`xcode-select --install`) or Swift 5.9+

### Build & Install

#### Option 1: Swift Package Manager (Recommended)
```bash
git clone https://github.com/kapilthakare-cyberpunk/totpbar.git
cd totpbar
swift build -c release
cp .build/release/totpbar /usr/local/bin/  # or ~/.local/bin/
```

#### Option 2: Direct Single-File Compilation
```bash
swiftc -O -framework Cocoa -framework CryptoKit TOTPBar.swift -o totpbar
cp totpbar /usr/local/bin/
```

Run directly:
```bash
totpbar &
```

---

## Configuration

TOTPBar stores configuration in standard user directories:
- **Accounts:** `~/.config/totp/accounts.txt`
- **Pinned Favorites:** `~/.config/totp/favorites.txt`

### Adding Accounts

Click **Open accounts file** from the TOTPBar menu (or open `~/.config/totp/accounts.txt` directly) and paste standard `otpauth://` URIs:

```text
otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub
otpauth://totp/AWS:admin?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=AWS&digits=6&period=30
otpauth://totp/Google:user@gmail.com?secret=NBSWY3DPEHPK3PXP&algorithm=SHA256
```

### Supported Parameters (RFC 6238)

| Query Parameter | Default | Supported Values |
| :--- | :--- | :--- |
| `secret` | *(Required)* | Base32 encoded secret key |
| `issuer` | Parsed from label | Any string identifier |
| `digits` | `6` | `6` to `8` digits |
| `period` | `30` | Refresh cycle in seconds |
| `algorithm` | `SHA1` | `SHA1`, `SHA256`, `SHA512` |

---

## Usage

| Action | Result |
| :--- | :--- |
| **Left Click** on an account | Copies the 2FA code to clipboard with 30s auto-clear |
| **`⌥` Option + Left Click** on an account | Toggles Pin/Unpin (moves to top menu) |
| **Open accounts file** | Opens `accounts.txt` in your default text editor |
| **Quit (`⌘Q`)** | Terminates the application |

---

## Launch on macOS Login (Optional)

To start TOTPBar automatically on login without maintaining LaunchAgent plists:

1. Open **System Settings ▸ General ▸ Login Items**.
2. Under **Open at Login**, click `+` and select the compiled `totpbar` binary or application bundle.

Or create `~/Library/LaunchAgents/com.user.totpbar.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.user.totpbar</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/totpbar</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>
```
Load the agent:
```bash
launchctl load ~/Library/LaunchAgents/com.user.totpbar.plist
```

---

## Security Model

1. **Sandboxing & Network**: Standard TOTP computation is 100% offline. Secrets never leave your machine.
2. **File Permissions**: The configuration directory (`~/.config/totp/`) is created with strict POSIX permissions (`0600`) restricting access exclusively to your macOS user account.
3. **Concealed Pasteboard**: Prevents third-party clipboard utilities from persisting temporary 2FA tokens.

---

## License

This project is licensed under the [MIT License](LICENSE).
