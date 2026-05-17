#!/usr/bin/env python3
"""
iobroker.blinkcam — blinkpy worker (sidecar).

Wraps the maintained `blinkpy` library so the ioBroker (Node) adapter never has
to reimplement Blink's reverse-engineered OAuth2/PKCE/2FA flow itself. When Blink
changes something, `pip install -U blinkpy` keeps this working — same library
Home Assistant uses.

Protocol: newline-delimited JSON (NDJSON).
  stdin  : one command object per line
  stdout : one event object per line  (NOTHING else ever goes to stdout)
  stderr : human/log output only

Commands (stdin):
  {"cmd":"login","username":"..","password":".."}   start/refresh session
  {"cmd":"twofa","code":"123456"}                    submit one-time 2FA code
  {"cmd":"poll"}                                     refresh + emit battery/state
  {"cmd":"snapshot","camera":"Name"}                 snap_picture (fresh "now" foto)
  {"cmd":"thumbnail","camera":"Name"}                Blink motion thumbnail (app image)
  {"cmd":"ping"}                                     liveness
  {"cmd":"shutdown"}                                 clean exit

Events (stdout):
  {"event":"ready"}
  {"event":"need_2fa"}
  {"event":"logged_in","cameras":[...]}
  {"event":"state","cameras":[{name,battery,battery_voltage,wifi,thumbnail,
                               motion_detected,temperature,serial,...}]}
  {"event":"snapshot","camera":"..","jpeg_b64":"..","ts":<unix>}
  {"event":"pong"}
  {"event":"error","where":"..","msg":".."}
  {"event":"bye"}

Credentials/token persistence: --creds <path>. After a successful (re)login the
blinkpy login attributes (incl. refresh_token + hardware_id) are written there
with 0600 perms, so 2FA is required only ONCE; later starts use the refresh
token. Username/password arrive over stdin (never argv/env) so they cannot leak
via `ps`.
"""

import argparse
import asyncio
import base64
import json
import os
import sys
import time
import logging

import aiohttp

from blinkpy.blinkpy import Blink
from blinkpy.auth import Auth
from blinkpy.helpers.util import json_load
from blinkpy.auth import (
    BlinkTwoFARequiredError,
    LoginError,
    TokenRefreshFailed,
    UnauthorizedError,
)

# blinkpy logs via the root/_LOGGER; force everything to stderr so stdout stays
# a clean NDJSON channel.
logging.basicConfig(
    level=logging.WARNING,
    stream=sys.stderr,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
LOG = logging.getLogger("blink_worker")

# How long to wait after snap_picture() for Blink's cloud to render the new
# thumbnail before we pull it (Blink is cloud-only, ~10-30 s latency).
SNAP_WAIT_S = 18


def emit(obj):
    """Write exactly one JSON event line to stdout and flush."""
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def cam_state(cam):
    """Pick the non-secret, useful attributes from a blinkpy camera."""
    a = cam.attributes
    return {
        "name": a.get("name"),
        "serial": a.get("serial"),
        "camera_id": a.get("camera_id"),
        "network_id": a.get("network_id"),
        "sync_module": a.get("sync_module"),
        "battery": a.get("battery"),                 # "ok" / "low"
        "battery_voltage": a.get("battery_voltage"),  # 1/100 V (165 = 1.65V)
        "wifi_strength": a.get("wifi_strength"),
        "temperature": a.get("temperature"),
        "motion_enabled": a.get("motion_enabled"),
        "motion_detected": a.get("motion_detected"),
        "thumbnail": a.get("thumbnail"),
        "last_record": a.get("last_record"),
        "type": a.get("type"),
    }


async def stdin_lines():
    """Async generator yielding decoded lines from stdin."""
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    while True:
        raw = await reader.readline()
        if not raw:  # EOF -> parent gone
            return
        line = raw.decode("utf-8", "replace").strip()
        if line:
            yield line


class Worker:
    def __init__(self, creds_path):
        self.creds_path = creds_path
        self.session = None
        self.blink = None

    async def _new_blink(self):
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
        self.blink = Blink(session=self.session)

    async def _save_creds(self):
        """Persist login attributes (token+refresh_token+hardware_id) 0600."""
        try:
            await self.blink.save(self.creds_path)
            os.chmod(self.creds_path, 0o600)
            LOG.info("Credentials/token persisted to %s (0600)", self.creds_path)
        except Exception as e:  # noqa: BLE001
            LOG.error("Could not persist credentials: %s", e)

    async def cmd_login(self, username, password):
        await self._new_blink()

        # 1) Try saved token (refresh path -> no 2FA) if a creds file exists.
        saved = None
        if self.creds_path and os.path.exists(self.creds_path):
            saved = await json_load(self.creds_path)
        if saved and saved.get("refresh_token"):
            login_data = dict(saved)
            login_data.setdefault("username", username)
            login_data.setdefault("password", password)
            self.blink.auth = Auth(
                login_data, no_prompt=True, session=self.session
            )
            try:
                ok = await self.blink.start()
                if ok:
                    await self._save_creds()  # rotate refreshed token
                    emit({"event": "logged_in",
                          "via": "refresh_token",
                          "cameras": list(self.blink.cameras.keys())})
                    return
                LOG.warning("Refresh-token start() returned False; "
                            "falling back to fresh login.")
            except (LoginError, TokenRefreshFailed, UnauthorizedError) as e:
                LOG.warning("Refresh-token login failed (%s); "
                            "falling back to fresh login.", e)
            # fall through to fresh login
            await self._new_blink()

        # 2) Fresh login with username/password (may require 2FA).
        if not username or not password:
            emit({"event": "error", "where": "login",
                  "msg": "no_credentials"})
            return
        self.blink.auth = Auth(
            {"username": username, "password": password},
            no_prompt=True,
            session=self.session,
        )
        try:
            ok = await self.blink.start()
        except BlinkTwoFARequiredError:
            emit({"event": "need_2fa"})
            return
        except UnauthorizedError:
            emit({"event": "error", "where": "login",
                  "msg": "invalid_credentials"})
            return
        except (LoginError, TokenRefreshFailed) as e:
            emit({"event": "error", "where": "login", "msg": str(e)})
            return

        if not ok:
            # Fresh password path: 2FA would have raised, a real login would
            # have returned True. False here is overwhelmingly a rejected
            # username/password (Cloudflare is reachable — proven in tests).
            emit({"event": "error", "where": "login",
                  "msg": "login_failed_check_credentials"})
            return
        await self._save_creds()
        emit({"event": "logged_in", "via": "password",
              "cameras": list(self.blink.cameras.keys())})

    async def cmd_twofa(self, code):
        if not self.blink:
            emit({"event": "error", "where": "twofa",
                  "msg": "no_login_in_progress"})
            return
        if getattr(self.blink, "available", False):
            # Already authenticated — 2FA state is consumed. Idempotent.
            emit({"event": "logged_in", "via": "already",
                  "cameras": list(self.blink.cameras.keys())})
            return
        try:
            ok = await self.blink.send_2fa_code(str(code))
        except Exception as e:  # noqa: BLE001
            emit({"event": "error", "where": "twofa", "msg": str(e)})
            return
        if not ok:
            emit({"event": "error", "where": "twofa",
                  "msg": "twofa_failed"})
            return
        await self._save_creds()
        emit({"event": "logged_in", "via": "2fa",
              "cameras": list(self.blink.cameras.keys())})

    async def cmd_poll(self):
        if not self.blink or not self.blink.available:
            emit({"event": "error", "where": "poll",
                  "msg": "not_logged_in"})
            return
        try:
            await self.blink.refresh(force=True)
        except Exception as e:  # noqa: BLE001
            emit({"event": "error", "where": "poll", "msg": str(e)})
            return
        cams = [cam_state(c) for c in self.blink.cameras.values()]
        emit({"event": "state", "ts": int(time.time()), "cameras": cams})

    async def cmd_snapshot(self, camera):
        if not self.blink or not self.blink.available:
            emit({"event": "error", "where": "snapshot",
                  "msg": "not_logged_in"})
            return
        cam = self.blink.cameras.get(camera)
        if cam is None:
            emit({"event": "error", "where": "snapshot",
                  "msg": "unknown_camera:%s" % camera})
            return
        try:
            await cam.snap_picture()              # ask Blink for a new image
            await asyncio.sleep(SNAP_WAIT_S)      # cloud render latency
            await self.blink.refresh(force=True)  # update thumbnail URL
            resp = await cam.get_media()          # download jpeg
            if not resp or resp.status != 200:
                emit({"event": "error", "where": "snapshot",
                      "msg": "media_http_%s" % (resp.status if resp else "none")})
                return
            data = await resp.read()
        except Exception as e:  # noqa: BLE001
            emit({"event": "error", "where": "snapshot", "msg": str(e)})
            return
        emit({
            "event": "snapshot",
            "camera": camera,
            "ts": int(time.time()),
            "jpeg_b64": base64.b64encode(data).decode("ascii"),
            "bytes": len(data),
        })

    async def cmd_thumbnail(self, camera):
        # Blinks Bewegungs-Thumbnail (das Bild aus der Blink-App: zeigt die
        # letzte Bewegung/Person). KEIN snap_picture -> kein "Aufwach-Foto".
        # blinkpy: refresh() aktualisiert cam.thumbnail; get_media() lädt es.
        if not self.blink or not self.blink.available:
            emit({"event": "error", "where": "thumbnail",
                  "msg": "not_logged_in"})
            return
        cam = self.blink.cameras.get(camera)
        if cam is None:
            emit({"event": "error", "where": "thumbnail",
                  "msg": "unknown_camera:%s" % camera})
            return
        try:
            await self.blink.refresh(force=True)   # cam.thumbnail = letzte Bewegung
            resp = await cam.get_media()            # lädt cam.thumbnail (kein snap)
            if not resp or resp.status != 200:
                emit({"event": "error", "where": "thumbnail",
                      "msg": "media_http_%s" % (resp.status if resp else "none")})
                return
            data = await resp.read()
        except Exception as e:  # noqa: BLE001
            emit({"event": "error", "where": "thumbnail", "msg": str(e)})
            return
        # Gleiches Event-Schema wie snapshot -> Adapter/Brain/Display unverändert.
        emit({
            "event": "snapshot",
            "camera": camera,
            "ts": int(time.time()),
            "jpeg_b64": base64.b64encode(data).decode("ascii"),
            "bytes": len(data),
            "src": "thumbnail",
        })

    async def close(self):
        try:
            if self.session and not self.session.closed:
                await self.session.close()
        except Exception:  # noqa: BLE001
            pass


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--creds", required=True,
                    help="path to token/credentials json (0600)")
    args = ap.parse_args()

    worker = Worker(args.creds)
    emit({"event": "ready"})

    try:
        async for line in stdin_lines():
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                emit({"event": "error", "where": "parse",
                      "msg": "bad_json"})
                continue
            cmd = msg.get("cmd")
            if cmd == "ping":
                emit({"event": "pong"})
            elif cmd == "login":
                await worker.cmd_login(
                    msg.get("username"), msg.get("password"))
            elif cmd == "twofa":
                await worker.cmd_twofa(msg.get("code"))
            elif cmd == "poll":
                await worker.cmd_poll()
            elif cmd == "snapshot":
                await worker.cmd_snapshot(msg.get("camera"))
            elif cmd == "thumbnail":
                await worker.cmd_thumbnail(msg.get("camera"))
            elif cmd == "shutdown":
                break
            else:
                emit({"event": "error", "where": "dispatch",
                      "msg": "unknown_cmd:%s" % cmd})
    finally:
        await worker.close()
        emit({"event": "bye"})


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
