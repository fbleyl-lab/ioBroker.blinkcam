"use strict";

/*
 * ioBroker.blinkcam — main adapter
 *
 * Strategy (verified 2026-05-16): Blink has no official API. The maintained
 * `blinkpy` library (the one Home Assistant uses) handles the reverse-engineered
 * OAuth2/PKCE/2FA flow and passes Cloudflare cleanly. So this adapter does NOT
 * reimplement Blink auth in Node — it runs a Python sidecar (python/blink_worker.py)
 * that wraps blinkpy and talks NDJSON over stdin/stdout. When Blink changes
 * something, bumping `blinkpyVersion` + restart re-provisions the venv.
 *
 * Hardening:
 *  - token (refresh_token) persisted by the worker -> 2FA needed only ONCE
 *  - credentials sent to the worker over stdin only (never argv/env -> no `ps` leak)
 *  - NO tight login retry loop: stop on credential failure (account safety),
 *    backoff only on transient/process crashes
 *  - password stored encrypted by ioBroker (encryptedNative)
 */

const utils = require("@iobroker/adapter-core");
const { spawn, spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const MAX_FAST_RESTARTS = 5;
const FAST_RESTART_MS = 4000;
const SLOW_RESTART_MS = 60000;

class BlinkCam extends utils.Adapter {
    constructor(options) {
        super({ ...options, name: "blinkcam" });
        this.worker = null;
        this.stdoutBuf = "";
        this.pollTimer = null;
        this.restartTimer = null;
        this.loggedIn = false;
        this.stopped = false; // hard stop (bad creds) — do not restart
        this.workerRestarts = 0;
        this.knownCameras = new Set();
        this.lastMotion = {};
        this.on("ready", this.onReady.bind(this));
        this.on("stateChange", this.onStateChange.bind(this));
        this.on("unload", this.onUnload.bind(this));
    }

    async onReady() {
        await this.setStateAsync("info.connection", false, true);
        await this.setStateAsync("info.twoFactorRequired", false, true);

        // Persistent per-instance directory: iobroker-data/blinkcam.<n>/
        this.dataDir = utils.getAbsoluteInstanceDataDir(this);
        try {
            fs.mkdirSync(this.dataDir, { recursive: true });
        } catch (e) {
            this.log.error(`Cannot create data dir ${this.dataDir}: ${e.message}`);
            return;
        }
        this.credsPath = path.join(this.dataDir, "creds.json");
        this.venvDir = path.join(this.dataDir, "venv");
        this.workerScript = path.join(__dirname, "python", "blink_worker.py");

        if (!this.config.username || !this.config.password) {
            this.log.error(
                "Blink username/password not configured. Open the adapter settings."
            );
            return;
        }

        // Global snapshot trigger (all cameras at once)
        await this.setObjectNotExistsAsync("snapshotTrigger", {
            type: "state",
            common: {
                name: "Take a fresh snapshot of ALL cameras",
                role: "button",
                type: "boolean",
                read: false,
                write: true,
                def: false,
            },
            native: {},
        });

        const py = this.ensureVenv();
        if (!py) {
            this.log.error(
                "Python/blinkpy provisioning failed. Need python3 + venv on the host. See log above."
            );
            return;
        }
        this.pythonExe = py;

        this.subscribeStates("twoFactorCode");
        this.subscribeStates("snapshotTrigger");
        this.subscribeStates("cameras.*.snapshotTrigger");

        this.startWorker();
    }

    /**
     * Ensure a venv with the pinned blinkpy exists; return path to its python.
     * Reuses the venv if blinkpy is already at the pinned version (fast restart).
     */
    ensureVenv() {
        const want = String(this.config.blinkpyVersion || "0.25.5");
        const venvPy = path.join(this.venvDir, "bin", "python3");

        const check = () => {
            if (!fs.existsSync(venvPy)) return false;
            const r = spawnSync(
                venvPy,
                ["-c", "import importlib.metadata as m;print(m.version('blinkpy'))"],
                { encoding: "utf8" }
            );
            return r.status === 0 && r.stdout.trim() === want;
        };

        if (check()) {
            this.log.info(`Reusing venv (blinkpy ${want}) at ${this.venvDir}`);
            return venvPy;
        }

        const pyBin = String(this.config.pythonBin || "python3");
        const dbg = (label, r) =>
            this.log.error(
                `${label}: status=${r.status} ` +
                `err=${r.error ? r.error.message : "-"} ` +
                `stdout=${(r.stdout || "").trim() || "-"} ` +
                `stderr=${(r.stderr || "").trim() || "-"}`
            );

        // 0) Is python3 even there?
        const ver = spawnSync(pyBin, ["--version"], { encoding: "utf8" });
        if (ver.error || ver.status !== 0) {
            dbg(`Python not runnable ('${pyBin}')`, ver);
            this.log.error(
                `Fix on the ioBroker host: install Python 3 ` +
                `(Debian/Ubuntu: sudo apt-get install -y python3 python3-venv python3-pip), ` +
                `then restart this instance.`
            );
            return null;
        }
        this.log.info(
            `Python OK: ${(ver.stdout || ver.stderr || "").trim()} — ` +
            `provisioning venv at ${this.venvDir} with blinkpy==${want} (one-time, ~1 min)…`
        );

        // 1) Is the venv/ensurepip module present? (Debian ships python3
        //    WITHOUT it by default — this is the usual failure.)
        const ep = spawnSync(pyBin, ["-c", "import ensurepip, venv"], {
            encoding: "utf8",
        });
        if (ep.status !== 0) {
            dbg("venv/ensurepip module missing", ep);
            this.log.error(
                "ROOT CAUSE: the Python 'venv' module is not installed on the " +
                "ioBroker host. Fix (one-time, needs host root):  " +
                "sudo apt-get update && sudo apt-get install -y python3-venv python3-pip  " +
                "— then restart the blinkcam instance. (Other distros: install the " +
                "python3 venv/pip packages accordingly.)"
            );
            return null;
        }

        const mk = spawnSync(pyBin, ["-m", "venv", this.venvDir], {
            encoding: "utf8",
        });
        if (mk.status !== 0 || mk.error) {
            dbg(`'${pyBin} -m venv' failed`, mk);
            this.log.error(
                "Fix on the ioBroker host (one-time, needs root):  " +
                "sudo apt-get update && sudo apt-get install -y python3-venv python3-pip  " +
                "— then restart the blinkcam instance."
            );
            return null;
        }
        const pip = spawnSync(
            venvPy,
            ["-m", "pip", "install", "--quiet", "--upgrade", `blinkpy==${want}`],
            { encoding: "utf8" }
        );
        if (pip.status !== 0 || pip.error) {
            dbg(`pip install blinkpy==${want} failed`, pip);
            this.log.error(
                "If this is a network/proxy issue, ensure the host can reach " +
                "pypi.org; otherwise install build deps. Then restart the instance."
            );
            return null;
        }
        if (!check()) {
            this.log.error(
                "venv created but blinkpy not importable at the expected version."
            );
            return null;
        }
        this.log.info("venv + blinkpy ready.");
        return venvPy;
    }

    startWorker() {
        if (this.stopped) return;
        this.log.debug(`Spawning worker: ${this.pythonExe} ${this.workerScript}`);
        this.worker = spawn(
            this.pythonExe,
            [this.workerScript, "--creds", this.credsPath],
            { stdio: ["pipe", "pipe", "pipe"] }
        );
        this.stdoutBuf = "";

        this.worker.stdout.on("data", (c) => this.onWorkerStdout(c));
        this.worker.stderr.on("data", (d) =>
            this.log.debug(`[py] ${d.toString("utf8").trimEnd()}`)
        );
        this.worker.on("error", (e) =>
            this.log.error(`Worker spawn error: ${e.message}`)
        );
        this.worker.on("exit", (code, sig) => this.onWorkerExit(code, sig));
    }

    onWorkerExit(code, sig) {
        this.loggedIn = false;
        this.setState("info.connection", false, true);
        if (this.pollTimer) {
            this.clearInterval(this.pollTimer);
            this.pollTimer = null;
        }
        if (this.stopped) {
            this.log.warn(`Worker exited (${code}/${sig}); not restarting (stopped).`);
            return;
        }
        this.workerRestarts++;
        const delay =
            this.workerRestarts <= MAX_FAST_RESTARTS
                ? FAST_RESTART_MS
                : SLOW_RESTART_MS;
        this.log.warn(
            `Worker exited (code=${code} sig=${sig}); restart #${this.workerRestarts} in ${delay / 1000}s.`
        );
        this.restartTimer = this.setTimeout(() => this.startWorker(), delay);
    }

    onWorkerStdout(chunk) {
        this.stdoutBuf += chunk.toString("utf8");
        let nl;
        while ((nl = this.stdoutBuf.indexOf("\n")) >= 0) {
            const line = this.stdoutBuf.slice(0, nl).trim();
            this.stdoutBuf = this.stdoutBuf.slice(nl + 1);
            if (!line) continue;
            let ev;
            try {
                ev = JSON.parse(line);
            } catch {
                this.log.debug(`Non-JSON from worker: ${line}`);
                continue;
            }
            this.handleEvent(ev).catch((e) =>
                this.log.error(`handleEvent ${ev && ev.event}: ${e.message}`)
            );
        }
    }

    send(obj) {
        if (this.worker && this.worker.stdin.writable) {
            this.worker.stdin.write(JSON.stringify(obj) + "\n");
        }
    }

    async handleEvent(ev) {
        switch (ev.event) {
            case "ready":
                this.send({
                    cmd: "login",
                    username: this.config.username,
                    password: this.config.password,
                });
                break;

            case "need_2fa":
                await this.setStateAsync("info.twoFactorRequired", true, true);
                this.log.warn(
                    "Blink requires a one-time 2FA code. Enter it in state " +
                    `${this.namespace}.twoFactorCode (Objects tab) — needed only once.`
                );
                break;

            case "logged_in": {
                this.loggedIn = true;
                this.workerRestarts = 0;
                await this.setStateAsync("info.connection", true, true);
                await this.setStateAsync("info.twoFactorRequired", false, true);
                this.log.info(
                    `Logged in via ${ev.via}. Cameras: ${(ev.cameras || []).join(", ") || "(none yet)"}`
                );
                this.startPolling();
                this.send({ cmd: "poll" }); // immediate first poll
                break;
            }

            case "state":
                await this.updateCameras(ev.cameras || []);
                break;

            case "snapshot":
                await this.writeSnapshot(ev);
                break;

            case "pong":
                break;

            case "error":
                this.handleWorkerError(ev);
                break;

            case "bye":
                this.log.debug("Worker said bye.");
                break;

            default:
                this.log.debug(`Unknown worker event: ${JSON.stringify(ev)}`);
        }
    }

    handleWorkerError(ev) {
        const msg = ev.msg || "";
        if (
            ev.where === "login" &&
            (msg === "login_failed_check_credentials" ||
                msg === "invalid_credentials" ||
                msg === "no_credentials")
        ) {
            // Account safety: do NOT loop logins. Stop and require a config fix.
            this.stopped = true;
            this.log.error(
                `Blink login rejected (${msg}). Check username/password in the ` +
                `adapter settings. Adapter stopped to protect the account ` +
                `(no automatic retry).`
            );
            if (this.worker) this.send({ cmd: "shutdown" });
            return;
        }
        if (ev.where === "poll" && msg === "not_logged_in") {
            this.log.debug("poll before login — ignoring.");
            return;
        }
        this.log.warn(`Worker error [${ev.where}]: ${msg}`);
    }

    startPolling() {
        if (this.pollTimer) this.clearInterval(this.pollTimer);
        const min = Math.max(1, Number(this.config.pollIntervalMinutes) || 5);
        this.pollTimer = this.setInterval(
            () => this.send({ cmd: "poll" }),
            min * 60000
        );
        this.log.info(`Polling every ${min} min.`);
    }

    cid(name) {
        return String(name || "cam").replace(this.FORBIDDEN_CHARS, "_").replace(/\s+/g, "_");
    }

    async ensureCameraObjects(name) {
        const id = this.cid(name);
        if (this.knownCameras.has(id)) return id;
        const base = `cameras.${id}`;
        await this.setObjectNotExistsAsync(`cameras`, {
            type: "channel",
            common: { name: "Cameras" },
            native: {},
        });
        await this.setObjectNotExistsAsync(base, {
            type: "channel",
            common: { name },
            native: {},
        });
        const S = async (sfx, common) =>
            this.setObjectNotExistsAsync(`${base}.${sfx}`, {
                type: "state",
                common,
                native: {},
            });
        await S("battery", { name: "Battery state", role: "indicator.battery", type: "string", read: true, write: false });
        await S("batteryVoltage", { name: "Battery voltage (1/100 V)", role: "value.voltage", type: "number", read: true, write: false, unit: "cV" });
        await S("wifiStrength", { name: "WiFi strength", role: "value", type: "number", read: true, write: false });
        await S("temperature", { name: "Temperature", role: "value.temperature", type: "number", read: true, write: false, unit: "°F" });
        await S("motionDetected", { name: "Motion detected", role: "sensor.motion", type: "boolean", read: true, write: false });
        await S("motionEnabled", { name: "Motion detection armed", role: "indicator", type: "boolean", read: true, write: false });
        await S("thumbnailUrl", { name: "Blink thumbnail URL", role: "text.url", type: "string", read: true, write: false });
        await S("snapshot", { name: "Snapshot (data URI, base64 JPEG)", role: "text", type: "string", read: true, write: false });
        await S("snapshotTime", { name: "Snapshot timestamp", role: "value.time", type: "number", read: true, write: false });
        await S("lastUpdate", { name: "Last data update", role: "value.time", type: "number", read: true, write: false });
        await S("snapshotTrigger", { name: "Take a fresh snapshot of this camera", role: "button", type: "boolean", read: false, write: true, def: false });
        this.knownCameras.add(id);
        return id;
    }

    async updateCameras(cams) {
        for (const c of cams) {
            const id = await this.ensureCameraObjects(c.name);
            const b = `cameras.${id}`;
            await this.setStateChangedAsync(`${b}.battery`, c.battery ?? null, true);
            await this.setStateChangedAsync(`${b}.batteryVoltage`, c.battery_voltage ?? null, true);
            await this.setStateChangedAsync(`${b}.wifiStrength`, c.wifi_strength ?? null, true);
            await this.setStateChangedAsync(`${b}.temperature`, c.temperature ?? null, true);
            await this.setStateChangedAsync(`${b}.motionEnabled`, !!c.motion_enabled, true);
            await this.setStateChangedAsync(`${b}.thumbnailUrl`, c.thumbnail ?? null, true);
            const motion = !!c.motion_detected;
            await this.setStateChangedAsync(`${b}.motionDetected`, motion, true);
            await this.setStateAsync(`${b}.lastUpdate`, Date.now(), true);

            // Rising-edge motion -> auto snapshot (configurable)
            const prev = this.lastMotion[id] || false;
            this.lastMotion[id] = motion;
            if (this.config.snapshotOnMotion && motion && !prev) {
                this.log.info(`Motion on '${c.name}' -> requesting snapshot.`);
                this.send({ cmd: "snapshot", camera: c.name });
            }
        }
    }

    async writeSnapshot(ev) {
        const id = await this.ensureCameraObjects(ev.camera);
        const b = `cameras.${id}`;
        const dataUri = `data:image/jpeg;base64,${ev.jpeg_b64}`;
        await this.setStateAsync(`${b}.snapshot`, dataUri, true);
        await this.setStateAsync(`${b}.snapshotTime`, (ev.ts || Math.floor(Date.now() / 1000)) * 1000, true);
        this.log.info(`Snapshot '${ev.camera}' updated (${ev.bytes} B).`);
    }

    async onStateChange(id, state) {
        if (!state || state.ack) return;
        const local = id.split(".").slice(2).join(".");

        if (local === "twoFactorCode") {
            const code = String(state.val || "").trim();
            if (!code) return;
            if (this.loggedIn) {
                // Already authenticated — a second code would just fail in
                // blinkpy (2FA state already consumed). Ignore quietly.
                this.log.debug("Already logged in — ignoring 2FA code entry.");
                await this.setStateAsync("twoFactorCode", "", true);
                return;
            }
            this.log.info("Submitting 2FA code…");
            this.send({ cmd: "twofa", code });
            await this.setStateAsync("twoFactorCode", "", true); // don't keep it
            return;
        }
        if (local === "snapshotTrigger") {
            for (const camId of this.knownCameras) {
                const o = await this.getObjectAsync(`cameras.${camId}`);
                this.send({ cmd: "snapshot", camera: (o && o.common && o.common.name) || camId });
            }
            // Reset the momentary button so it can fire again next time.
            await this.setStateAsync("snapshotTrigger", false, true);
            return;
        }
        const m = local.match(/^cameras\.([^.]+)\.snapshotTrigger$/);
        if (m) {
            const camId = m[1];
            const o = await this.getObjectAsync(`cameras.${camId}`);
            this.send({ cmd: "snapshot", camera: (o && o.common && o.common.name) || camId });
            // Reset the momentary button (stateChange only fires on change).
            await this.setStateAsync(`cameras.${camId}.snapshotTrigger`, false, true);
        }
    }

    onUnload(callback) {
        try {
            this.stopped = true;
            if (this.pollTimer) this.clearInterval(this.pollTimer);
            if (this.restartTimer) this.clearTimeout(this.restartTimer);
            if (this.worker) {
                try {
                    this.send({ cmd: "shutdown" });
                } catch {
                    /* ignore */
                }
                const w = this.worker;
                this.worker = null;
                setTimeout(() => {
                    try {
                        w.kill("SIGTERM");
                    } catch {
                        /* ignore */
                    }
                }, 800);
            }
            this.setState("info.connection", false, true);
        } finally {
            callback();
        }
    }
}

if (require.main !== module) {
    module.exports = (options) => new BlinkCam(options);
} else {
    new BlinkCam();
}
