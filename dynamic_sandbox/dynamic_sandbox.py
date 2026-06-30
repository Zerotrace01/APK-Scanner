"""
DroidScan — Module 2: Dynamic Sandbox
======================================
Runs the APK in an isolated Android emulator and captures:
  - Network traffic (via mitmproxy)
  - Runtime API calls (via Frida hooks)
  - File system mutations
  - SMS / call activity

Prerequisites:
    pip install frida frida-tools mitmproxy adbutils
    Android SDK with AVD emulator configured
    Start emulator: emulator -avd DroidScan_AVD -no-snapshot -writable-system

Usage:
    sandbox = DynamicSandbox("malware.apk")
    results = sandbox.run(timeout=120)
"""

import time
import json
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional

import frida
import adbutils
from mitmproxy import http as mhttp
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster


# ─── Frida hook script ────────────────────────────────────────────────────────

FRIDA_SCRIPT = """
'use strict';

function send_event(type, data) {
    send({ type: type, payload: data });
}

Java.perform(function () {

    // ── SMS sending ──────────────────────────────────────────────────────────
    var SmsManager = Java.use('android.telephony.SmsManager');
    SmsManager.sendTextMessage.overload(
        'java.lang.String','java.lang.String','java.lang.String',
        'android.app.PendingIntent','android.app.PendingIntent'
    ).implementation = function(dest, sc, text, si, di) {
        send_event('SMS_SEND', { destination: dest, body: text });
        return this.sendTextMessage(dest, sc, text, si, di);
    };

    // ── Shell execution ───────────────────────────────────────────────────────
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        send_event('SHELL_EXEC', { command: cmd });
        return this.exec(cmd);
    };
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmds) {
        send_event('SHELL_EXEC', { command: cmds.join(' ') });
        return this.exec(cmds);
    };

    // ── Device ID harvesting ─────────────────────────────────────────────────
    var TelephonyManager = Java.use('android.telephony.TelephonyManager');
    TelephonyManager.getDeviceId.overload().implementation = function() {
        var id = this.getDeviceId();
        send_event('DEVICE_ID_READ', { imei: id });
        return id;
    };
    TelephonyManager.getSubscriberId.overload().implementation = function() {
        var imsi = this.getSubscriberId();
        send_event('IMSI_READ', { imsi: imsi });
        return imsi;
    };

    // ── File write ───────────────────────────────────────────────────────────
    var FileOutputStream = Java.use('java.io.FileOutputStream');
    FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
        send_event('FILE_WRITE', { path: path });
        return this.$init(path);
    };

    // ── DexClassLoader ───────────────────────────────────────────────────────
    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    DexClassLoader.$init.implementation = function(dexPath, optDir, libPath, parent) {
        send_event('DEX_LOAD', { dex_path: dexPath });
        return this.$init(dexPath, optDir, libPath, parent);
    };

    // ── Crypto key generation ────────────────────────────────────────────────
    var KeyGenerator = Java.use('javax.crypto.KeyGenerator');
    KeyGenerator.generateKey.implementation = function() {
        var key = this.generateKey();
        send_event('CRYPTO_KEY_GEN', { algorithm: this.getAlgorithm() });
        return key;
    };

    // ── HTTP connections ─────────────────────────────────────────────────────
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function() {
        send_event('HTTP_CONNECT', { url: this.toString() });
        return this.openConnection();
    };

    console.log('[DroidScan] Frida hooks installed successfully');
});
"""


# ─── mitmproxy addon ──────────────────────────────────────────────────────────

class TrafficCapture:
    """mitmproxy addon — collects all HTTP requests/responses."""

    def __init__(self):
        self.requests: list = []

    def request(self, flow: mhttp.HTTPFlow):
        self.requests.append({
            "method":  flow.request.method,
            "url":     flow.request.pretty_url,
            "host":    flow.request.host,
            "port":    flow.request.port,
            "headers": dict(flow.request.headers),
            "body":    flow.request.content.decode("utf-8", errors="ignore")[:500],
            "ts":      datetime.utcnow().isoformat(),
        })

    def response(self, flow: mhttp.HTTPFlow):
        if self.requests:
            self.requests[-1]["response_status"] = flow.response.status_code
            self.requests[-1]["response_size"]   = len(flow.response.content)


class DynamicSandbox:
    """
    Runs APK in isolated Android emulator, captures runtime behaviour.

    Usage:
        sandbox = DynamicSandbox("malware.apk", avd_name="DroidScan_AVD")
        results = sandbox.run(timeout=120)
    """

    PROXY_PORT = 8888

    def __init__(self, apk_path: str, avd_name: str = "DroidScan_AVD",
                 serial: Optional[str] = None):
        self.apk_path      = Path(apk_path)
        self.avd_name      = avd_name
        self.serial        = serial
        self.adb_client    = None
        self.device        = None
        self.frida_events: list  = []
        self.traffic_addon = TrafficCapture()

    def run(self, timeout: int = 120) -> dict:
        print(f"[*] Starting dynamic sandbox for: {self.apk_path.name}")
        results: dict = {
            "frida_events":    [],
            "network_traffic": [],
            "file_mutations":  [],
            "sandbox_errors":  [],
            "duration_secs":   timeout,
            "timestamp":       datetime.utcnow().isoformat() + "Z",
        }
        try:
            self._start_emulator()
            self._setup_proxy()
            self._install_apk()
            self._attach_frida(timeout)
            results["frida_events"]    = self.frida_events
            results["network_traffic"] = self.traffic_addon.requests
            results["file_mutations"]  = [
                e for e in self.frida_events if e["type"] == "FILE_WRITE"
            ]
        except Exception as e:
            results["sandbox_errors"].append(str(e))
            print(f"[!] Sandbox error: {e}")
        finally:
            self._cleanup()
        print(f"[+] Dynamic analysis complete. Events: {len(self.frida_events)}, "
              f"Requests: {len(self.traffic_addon.requests)}")
        return results

    def _start_emulator(self):
        print(f"[*] Starting emulator: {self.avd_name}")
        subprocess.Popen([
            "emulator", "-avd", self.avd_name,
            "-no-snapshot", "-no-audio", "-no-window",
            "-http-proxy", f"127.0.0.1:{self.PROXY_PORT}",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[*] Waiting for emulator to boot...")
        subprocess.run(["adb", "wait-for-device"], timeout=120)
        time.sleep(10)
        self.adb_client = adbutils.AdbClient()
        devices = self.adb_client.device_list()
        if not devices:
            raise RuntimeError("No emulator device found after boot")
        self.device = devices[0]
        print(f"[+] Emulator ready: {self.device.serial}")

    def _setup_proxy(self):
        print(f"[*] Starting mitmproxy on port {self.PROXY_PORT}...")

        def run_proxy():
            opts   = Options(listen_host="127.0.0.1",
                             listen_port=self.PROXY_PORT,
                             ssl_insecure=True)
            master = DumpMaster(opts)
            master.addons.add(self.traffic_addon)
            try:
                master.run()
            except Exception:
                pass

        t = threading.Thread(target=run_proxy, daemon=True)
        t.start()
        time.sleep(2)

    def _install_apk(self):
        print(f"[*] Installing APK: {self.apk_path.name}")
        subprocess.run(
            ["adb", "-s", self.device.serial, "install", "-r", str(self.apk_path)],
            check=True, capture_output=True,
        )
        print("[+] APK installed")

    def _attach_frida(self, timeout: int):
        print("[*] Attaching Frida to target app...")
        package = self._get_package_name()
        subprocess.run([
            "adb", "-s", self.device.serial, "shell",
            f"monkey -p {package} -c android.intent.category.LAUNCHER 1",
        ], capture_output=True)
        time.sleep(3)
        try:
            device  = frida.get_usb_device(timeout=10)
            session = device.attach(package)
            script  = session.create_script(FRIDA_SCRIPT)

            def on_message(message, data):
                if message["type"] == "send":
                    self.frida_events.append({
                        "type": message["payload"]["type"],
                        "data": message["payload"]["payload"],
                        "ts":   datetime.utcnow().isoformat(),
                    })

            script.on("message", on_message)
            script.load()
            print(f"[+] Frida running. Observing for {timeout}s...")
            time.sleep(timeout)
            session.detach()
        except frida.ProcessNotFoundError:
            raise RuntimeError(f"App process not found: {package}")

    def _get_package_name(self) -> str:
        from androguard.misc import AnalyzeAPK
        apk, _, _ = AnalyzeAPK(str(self.apk_path))
        return apk.get_package()

    def _cleanup(self):
        print("[*] Cleaning up sandbox...")
        try:
            if self.device:
                pkg = self._get_package_name()
                subprocess.run(
                    ["adb", "-s", self.device.serial, "uninstall", pkg],
                    capture_output=True,
                )
            subprocess.run(["adb", "emu", "kill"], capture_output=True)
        except Exception:
            pass
        print("[+] Sandbox cleaned up")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python dynamic_sandbox.py <path/to/app.apk> [timeout_secs]")
        sys.exit(1)
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 120
    sandbox = DynamicSandbox(sys.argv[1])
    results = sandbox.run(timeout=timeout)
    out_file = Path(sys.argv[1]).stem + "_dynamic_results.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Results saved to {out_file}")
