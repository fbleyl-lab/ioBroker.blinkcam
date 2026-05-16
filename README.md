# ioBroker.blinkcam

Blink cameras in ioBroker: **motion snapshots** and **battery levels** as states.

## How it works (and why)

Blink has **no official API**. Every working Blink integration (including Home
Assistant's) uses the community library **[blinkpy](https://github.com/fronzbot/blinkpy)**,
which implements Blink's reverse-engineered OAuth2 + PKCE + 2FA flow.

This adapter does **not** reimplement that flow in Node (a pure-Node attempt
keeps hitting Cloudflare and breaks every time Blink changes something). Instead
it runs a small **Python sidecar** (`python/blink_worker.py`) that wraps
`blinkpy` and talks NDJSON over stdin/stdout. When Blink changes their flow,
bump the pinned `blinkpy` version in the settings and restart — no adapter code
change needed.

Verified 2026-05-16: blinkpy 0.25.5 passes Cloudflare cleanly; a dummy login is
rejected *behind* Cloudflare with HTTP 401 (no 406).

## Requirements

- ioBroker on **Linux** (tested target: Synology Linux VM)
- **Python 3** with the `venv` module on the host
  (Debian/Ubuntu: `sudo apt install python3 python3-venv`)
- Outbound HTTPS to `*.blink.com` / `*.immedia-semi.com`

On first start the adapter creates a private virtual-env in its instance data
dir and installs the pinned `blinkpy` automatically (one-time, ~1 min).

## Setup

1. Install the adapter, create an instance.
2. Settings → enter your **Blink e-mail + password** (password is stored
   encrypted by ioBroker).
3. Start the instance. On the **first** login Blink sends a **2FA code**
   (e-mail/SMS).
4. Open the **Objects** tab → set `blinkcam.<n>.twoFactorCode` to the code.
   The adapter completes login and **persists the refresh token** — you will
   **not** be asked for 2FA again on later restarts.

`info.connection = true` ⇒ logged in and the worker is alive.

## States

Per camera under `blinkcam.<n>.cameras.<name>.`:

| State            | Meaning                                             |
|------------------|-----------------------------------------------------|
| `battery`        | `ok` / `low`                                        |
| `batteryVoltage` | battery voltage in 1/100 V (165 = 1.65 V)           |
| `wifiStrength`   | Wi-Fi signal                                        |
| `temperature`    | camera temperature (°F, as Blink reports)           |
| `motionDetected` | motion flag from the last poll                      |
| `motionEnabled`  | motion detection armed                              |
| `thumbnailUrl`   | Blink's thumbnail URL                               |
| `snapshot`       | **`data:image/jpeg;base64,…`** — bind directly in VIS |
| `snapshotTime`   | timestamp of the snapshot                           |
| `lastUpdate`     | timestamp of the last data poll                     |
| `snapshotTrigger`| write `true` to fetch a fresh snapshot now          |

Global: `blinkcam.<n>.snapshotTrigger` snapshots all cameras at once.

Snapshots update automatically on motion when *Auto snapshot on motion* is on
(rising edge), and on demand via the trigger states. Battery/state refresh on
the configured poll interval (default 5 min).

## Sharing with a colleague

Share the whole `iobroker.blinkcam` folder (or the GitHub repo). The only host
prerequisite is **Python 3 + venv**; the adapter provisions its own blinkpy
venv. Each instance uses its own Blink account from its own settings.

## Honest limitations

- **Cloud only.** Blink has no local API. Snapshots come from Blink's cloud
  with ~10–30 s latency. No live stream (Blink limitation).
- **Reverse-engineered.** If Blink changes their flow, snapshots/battery may
  pause until a new `blinkpy` is released — then just bump the version and
  restart. This is the same risk every Blink integration has; wrapping the
  maintained library is the most robust available approach.
- No tight retry on bad credentials — the adapter **stops** on a rejected login
  to protect the account; fix the password in settings and restart.

## License

MIT
