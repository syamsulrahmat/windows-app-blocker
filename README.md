# AppBlocker

A simple Windows tool with a graphical interface that blocks selected applications from accessing the internet using **Windows Defender Firewall** rules.

## Features

- Type, paste, or browse for any `.exe` to block it with one click (inbound + outbound)
- Drag and drop `.exe` files directly into the window
- Distinguishes between different app versions sharing the same executable name (e.g. Adobe After Effects 2024 vs 2026)
- See and unblock currently blocked apps
- Shows Windows Firewall status and can turn it on (blocks only work while the firewall is on)
- Offers to close a running app after blocking it, so existing connections are dropped
- Rules are prefixed with `AppBlocker:` so they are easy to find in Windows Firewall

## Requirements

- Windows 10 / 11
- Windows PowerShell 5.1 (built in)
- Administrator rights (the launcher requests them automatically)

## Usage

1. Download or clone this repository.
2. Double-click **`AppBlocker.bat`** (or `AppBlocker.exe`) and accept the UAC prompt.
3. If prompted, turn on Windows Firewall.
4. Type/paste the path, drag and drop, or click **Browse...** to pick the app's `.exe`, then click **Block This App**.
5. To restore access, select the app in the list and click **Unblock Selected**.

## Notes

- Turning on Windows Firewall may block unsolicited incoming connections (e.g. file sharing or remote access) that don't already have allow rules.
- Some apps use helper processes or updaters with separate `.exe` files; you may need to block those too.
- You can review or remove the rules manually in **Windows Defender Firewall with Advanced Security** → Inbound/Outbound Rules (look for `AppBlocker:`).
