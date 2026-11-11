# Arthur WebSSH, SFTP & Mabar Terminal

Browser-based Interactive SSH Terminal, SFTP File Manager, Realtime Resource Telemetry, and 1-Link Multiplayer (Mabar SSH) terminal powered by Node.js, `ssh2`, `ws`, and `xterm.js`.

## Features
- **Interactive WebSSH**: Direct browser terminal (`xterm.js`) connected to the Main VPS (`root@arthurg.my.id`) or custom SSH servers.
- **Auto-Save / Auto-Login (`localStorage`)**: Seamless authentication shared with `/admin` (`arthur_admin_session` & `arthur_admin_pin`).
- **Session Management**: Create multiple SSH sessions/tabs and close/delete active sessions with confirmation.
- **SFTP File Manager**: Browse directories, edit files inline, upload/download, `chmod`, `mkdir`, and delete files.
- **Mabar SSH (1-Link Co-Pilot)**: Share a live terminal session via a single invite link with toggleable Co-Pilot (Read/Write) or Spectator (Read-Only) mode.
