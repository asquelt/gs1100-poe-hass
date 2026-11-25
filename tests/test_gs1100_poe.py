"""Testy na sucho: AES vs. wektor z oryginalnego aes-util, cały cykl na atrapie switcha.

    python3 -m unittest discover -s tests -v
"""
import contextlib
import io
import json
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gs1100_poe"))
import gs1100_poe as g  # noqa: E402

PASSWORD = "Abcdef123!xyz"
# Wygenerowane oryginalnym aes-util-CNB8NLUb.js z panelu: node, `import {e} from aes-util`, e(plaintext).
JS_VECTORS = json.loads(open(__file__.replace("test_gs1100_poe.py", "aes_vectors.json")).read())


class FakeSwitch(BaseHTTPRequestHandler):
    token = None
    logins = 0
    expire_next = False

    def log_message(self, *a):
        pass

    def _send(self, code, obj=None, cookie=None):
        body = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", f"sessionId={cookie};SameSite=Strict;path=/;HttpOnly;")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        form = urllib.parse.parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        cls = type(self)
        if self.headers.get("Origin") != f"http://{self.headers['Host']}":
            return self._send(403)
        if self.path == "/login.cgi":
            if form["password"][0] != g.encrypt_field(PASSWORD) or "seed" not in form:
                return self._send(200, {"status_msg": "Incorrect password, please try again!"})
            cls.logins += 1
            cls.token = f"tok{cls.logins}"
            return self._send(200, {"status_msg": "ok", "v": cls.token}, cookie=cls.token)
        if self.path == "/logout.cgi":
            cls.token = None
            return self._send(200, {"status_msg": "ok"})
        self._send(404)

    def do_GET(self):
        cls = type(self)
        if self.path == "/login_info.cgi":
            return self._send(200, {"model_name": "GS1100-16EP", "login_status": "0"})
        if cls.expire_next:
            cls.expire_next, cls.token = False, None
        if cls.token is None or self.headers.get("token") != cls.token \
                or self.headers.get("Cookie") != f"sessionId={cls.token}":
            return self._send(401)
        if self.path == "/sys_info.cgi":
            rows = [["Down", "0", "0", "Normal", "0"] for _ in range(16)]
            rows[0] = ["1000 Mbps", "12345", "678", "Normal", "7"]
            rows[3] = ["100 Mbps", "1", "2", "Normal", "12"]
            return self._send(200, {"status_msg": "ok", "data": {
                "model_name": "GS1100-16EP", "sys_dev_name": "szafa-1", "sys_fmw_ver": "V1.00",
                "sys_MAC": "00:11:22:33:44:55", "system_uptime": "4242",
                "total_power": "135", "left_power": "115", "max_led_power": "128",
                "port_status": rows}})
        if self.path == "/ports_info.cgi":
            return self._send(200, {"status_msg": "ok", "data": {"model_name": "GS1100-16EP",
                                                                  "portState": "0xffff", "portPoE": "0x9"}})
        self._send(404)


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), FakeSwitch)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.host = f"127.0.0.1:{cls.srv.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        FakeSwitch.token, FakeSwitch.logins, FakeSwitch.expire_next = None, 0, False

    def test_aes_matches_panel_js(self):
        self.assertGreaterEqual(len(JS_VECTORS), 5)
        for plain, expected in JS_VECTORS.items():
            self.assertEqual(g.encrypt_field(plain), expected, plain)

    def test_poll_and_relogin(self):
        sw = g.GS1100(self.host, PASSWORD)
        st = g.parse(sw.raw())
        self.assertEqual(st["ports"][0], {"link": "1000 Mbps", "poe_w": 7.0, "poe_enabled": "ON"})
        self.assertEqual(st["ports"][1]["poe_enabled"], "OFF")
        self.assertEqual(st["ports"][3]["poe_enabled"], "ON")
        self.assertEqual(st["poe_used"], 20)
        self.assertEqual(st["poe_power_left"], 115)
        self.assertEqual(st["poe_budget_pct"], 14.8)
        FakeSwitch.expire_next = True
        sw.raw()
        self.assertEqual(FakeSwitch.logins, 2)
        sw.logout()
        self.assertIsNone(FakeSwitch.token)

    def test_bad_password(self):
        with self.assertRaises(g.AuthError):
            g.GS1100(self.host, "ZleHaslo12345").raw()
        with self.assertRaises(g.AuthError):
            g.GS1100(self.host, "krotkie").login()

    def test_main_dry_run_publishes_discovery_and_state(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
            json.dump({"switches": [{"name": "Switch PoE 1", "host": self.host, "password": PASSWORD,
                                     "port_names": "4=Kamera 1, 9: Dzwonek; 16 = Uplink, 3="}]}, f)
            f.flush()
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = g.main(["-c", f.name, "--once", "-n"])
        self.assertEqual(rc, 0)
        msgs = dict(line.split(" ", 1) for line in out.getvalue().splitlines())
        disc = json.loads(msgs["homeassistant/device/gs1100_001122334455/config"])
        self.assertEqual(len(disc["components"]), 4 + 16 * 3)
        self.assertEqual(disc["components"]["p04_poe_w"]["value_template"], "{{ value_json.ports[3].poe_w }}")
        names = {k: c["name"] for k, c in disc["components"].items()}
        self.assertEqual(names["p04_poe_w"], "Port 4 – Kamera 1 PoE")
        self.assertEqual(names["p09_link"], "Port 9 – Dzwonek link")
        self.assertEqual(names["p16_poe_enabled"], "Port 16 – Uplink PoE włączone")
        self.assertEqual(names["p03_poe_w"], "Port 3 PoE")
        self.assertEqual(g.port_names({"2": "A"}), {2: "A"})
        self.assertEqual(g.port_names(["A", "", "C"]), {1: "A", 3: "C"})
        self.assertEqual(disc["device"]["connections"], [["mac", "00:11:22:33:44:55"]])
        self.assertEqual(disc["state_topic"], "gs1100/gs1100_001122334455/state")
        self.assertEqual(json.loads(msgs["gs1100/gs1100_001122334455/state"])["ports"][3]["poe_w"], 12)
        self.assertEqual(msgs["gs1100/gs1100_001122334455/availability"], "offline")  # po wyjściu


if __name__ == "__main__":
    unittest.main()
