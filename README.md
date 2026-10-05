# AppBlocker

A simple Windows tool with a graphical interface that blocks selected applications from accessing the internet using **Windows Defender Firewall** rules.

## Features

- Browse for any `.exe` and block it with one click (inbound + outbound)
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
2. Double-click **`AppBlocker.bat`** and accept the UAC prompt.
3. If prompted, turn on Windows Firewall.
4. Click **Browse...**, pick the app's `.exe`, then click **Block This App**.
5. To restore access, select the app in the list and click **Unblock Selected**.

## Notes

- Turning on Windows Firewall may block unsolicited incoming connections (e.g. file sharing or remote access) that don't already have allow rules.
- Some apps use helper processes or updaters with separate `.exe` files; you may need to block those too.
- You can review or remove the rules manually in **Windows Defender Firewall with Advanced Security** → Inbound/Outbound Rules (look for `AppBlocker:`).
