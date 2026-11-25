#!/usr/bin/env python3
"""Zyxel GS1100-16EP -> MQTT (Home Assistant discovery): PoE per port.

Protokół odtworzony z panelu WWW (bundle index-BBJ23RVh.js / aes-util-CNB8NLUb.js):

  * każde pole formularza POST jest szyfrowane AES-128-CBC stałym kluczem z JS-a
    (PKCS7, wynik w base64) -- to nie jest handshake, tylko zaciemnienie;
  * POST /login.cgi  password=<enc>&seed=<enc(losowy uint32)>
        -> {"status_msg":"ok","v":"<token>","f":<1 = wymuszona zmiana hasła>}
  * token idzie w nagłówku `token:` przy każdym żądaniu, do tego ciasteczko `sessionId`
    z odpowiedzi logowania; wysyłamy też Origin/Referer jak przeglądarka;
  * panel trzyma JEDNĄ sesję naraz: login przy cudzej aktywnej sesji = 403
    (poller i przeglądarka wzajemnie się blokują do wylogowania / timeoutu);
  * GET /sys_info.cgi   -> {"data":{total_power (budżet, "135"),left_power,max_led_power,
                            port_status:[["100 Mbps"|"Down",tx,rx,loop,"7" (W)], ...], sys_MAC, ...}}
  * GET /ports_info.cgi -> {"data":{portState,portPoE (maski bitowe jako "0xffff"), ...}}
  * 401/403/408 = sesja wygasła -> logujemy się ponownie.

Domyślnie poller wyłącznie czyta (2x GET na cykl). Z opcją `control: true` wystawia
przełączniki PoE / portu i wtedy woła POST /port_state_set.cgi (pola g_port_* = maski
wszystkich portów; zmieniamy jeden bit, resztę odsyłamy tak, jak przeczytaliśmy).
`protected_ports` wyłącza sterowanie wskazanymi portami.

Użycie:
  gs1100_poe.py --config config.json            # pętla: poll -> MQTT
  gs1100_poe.py --config config.json --dump     # zaloguj, wypisz surowy JSON, wyjdź
  gs1100_poe.py --config config.json --once -n  # jeden cykl, bez MQTT (stdout)
"""
from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import queue
import random
import re
import signal
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger("gs1100")

AES_KEY = b"iti01234567890sw"
AES_IV = b"sw01234567890iti"
NO_TOKEN = "tokeniserrorrrrr"  # to samo wysyła panel, gdy nie ma sesji
USER_AGENT = "Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
PASSWORD_RE = re.compile(r"^[a-zA-Z0-9~!@#$%\^&*()_+`\-={}\[\]:;<>./\\]{9,64}$")

# ---------------------------------------------------------------- AES-128-CBC


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _make_sbox() -> bytes:
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ _xtime(p)  # p *= 3
        q ^= q << 1  # q /= 3
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ (q << 1 | q >> 7) ^ (q << 2 | q >> 6) ^ (q << 3 | q >> 5) ^ (q << 4 | q >> 4)
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return bytes(sbox)


_SBOX = _make_sbox()


def _expand_key(key: bytes) -> list[bytes]:
    w = [key[i : i + 4] for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = w[i - 1]
        if i % 4 == 0:
            t = bytes(_SBOX[b] for b in t[1:] + t[:1])
            t = bytes([t[0] ^ rcon]) + t[1:]
            rcon = _xtime(rcon)
        w.append(bytes(a ^ b for a, b in zip(w[i - 4], t)))
    return [b"".join(w[i : i + 4]) for i in range(0, 44, 4)]


def _encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    s = bytes(a ^ b for a, b in zip(block, round_keys[0]))
    for rnd in range(1, 11):
        s = bytes(_SBOX[b] for b in s)
        s = bytes(s[(i + 4 * (i % 4)) % 16] for i in range(16))  # ShiftRows
        if rnd < 10:
            out = bytearray(16)
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c : c + 4]
                t = a0 ^ a1 ^ a2 ^ a3
                out[c] = a0 ^ t ^ _xtime(a0 ^ a1)
                out[c + 1] = a1 ^ t ^ _xtime(a1 ^ a2)
                out[c + 2] = a2 ^ t ^ _xtime(a2 ^ a3)
                out[c + 3] = a3 ^ t ^ _xtime(a3 ^ a0)
            s = bytes(out)
        s = bytes(a ^ b for a, b in zip(s, round_keys[rnd]))
    return s


_ROUND_KEYS = _expand_key(AES_KEY)


def encrypt_field(value: str) -> str:
    """Odpowiednik `e()` z aes-util: AES-128-CBC + PKCS7 -> base64."""
    data = value.encode()
    pad = 16 - len(data) % 16
    data += bytes([pad]) * pad
    prev, out = AES_IV, b""
    for i in range(0, len(data), 16):
        prev = _encrypt_block(bytes(a ^ b for a, b in zip(data[i : i + 16], prev)), _ROUND_KEYS)
        out += prev
    return base64.b64encode(out).decode()


# ---------------------------------------------------------------- klient HTTP


# pola POST /port_state_set.cgi <- klucze z GET /ports_info.cgi
PORT_FIELDS = (
    ("g_port_state", "portState"),
    ("g_port_speed_auto", "portSpeedAuto"),
    ("g_port_speed_10m", "portSpeed10M"),
    ("g_port_speed_100m", "portSpeed100M"),
    ("g_port_speed_1000m", "portSpeed1000M"),
    ("g_port_flwcl", "portFlctl"),
    ("g_port_poe", "portPoE"),
)


class AuthError(Exception):
    """Switch odrzucił hasło (albo wymaga jego zmiany) -- nie ponawiać szybko."""


class SessionExpired(Exception):
    pass


class GS1100:
    def __init__(self, host: str, password: str, timeout: float = 10.0):
        self.base = host if "://" in host else f"http://{host}"
        self.password = password
        self.timeout = timeout
        self.token: str | None = None
        self.cookie: str | None = None

    def _request(self, path: str, form: dict | None = None) -> dict:
        data = None
        # nagłówki jak z przeglądarki; sesja = token + ciasteczko
        headers = {
            "token": self.token or NO_TOKEN,
            "Accept": "application/json, text/plain, */*",
            "Origin": self.base,
            "Referer": self.base + "/",
            "User-Agent": USER_AGENT,
        }
        if self.cookie:
            headers["Cookie"] = self.cookie
        if form is not None:
            data = urllib.parse.urlencode({k: encrypt_field(str(v)) for k, v in form.items()}).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(self.base + path, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
                if resp.headers.get("Set-Cookie"):
                    self.cookie = resp.headers["Set-Cookie"].split(";", 1)[0]
        except urllib.error.HTTPError as e:
            e.close()
            if e.code in (401, 403, 408):
                self.token = self.cookie = None
                raise SessionExpired(f"{path}: HTTP {e.code}") from None
            raise
        return json.loads(body)

    def model(self) -> dict:
        return self._request("/login_info.cgi")

    def login(self) -> None:
        if not PASSWORD_RE.match(self.password):
            raise AuthError("hasło nie spełnia formatu panelu (9-64 znaki)")
        self.token = self.cookie = None
        try:
            r = self._request("/login.cgi", {"password": self.password, "seed": random.getrandbits(32)})
        except SessionExpired as e:
            raise AuthError(f"login odrzucony: {e}") from None
        if r.get("status_msg") != "ok" or not r.get("v"):
            raise AuthError(f"login odrzucony: {r.get('status_msg')!r}")
        self.token = r["v"]
        if r.get("f"):
            log.warning("%s: switch zgłasza pierwsze logowanie (f=%r) -- panel wymusi zmianę hasła", self.base, r["f"])

    def logout(self) -> None:
        if self.token:
            try:
                self._request("/logout.cgi", {"logout": 1})
            except Exception as e:  # noqa: BLE001 - best effort
                log.debug("logout: %s", e)
            self.token = self.cookie = None

    def get(self, path: str, form: dict | None = None) -> dict:
        """GET (albo POST, gdy podano form) z jednym ponownym logowaniem, gdy sesja wygasła."""
        for attempt in (0, 1):
            if not self.token:
                self.login()
            try:
                return self._request(path, form)
            except SessionExpired:
                if attempt:
                    raise
        raise AssertionError

    def set_port(self, port: int, kind: str, on: bool, nports: int = 16) -> bool:
        """Włącz/wyłącz PoE (kind="poe") albo sam port (kind="port"). Zwraca True, gdy coś zmieniono.

        Panel zapisuje wszystkie porty jednym POST-em (maski bitowe), więc czytamy bieżące
        ustawienia, zmieniamy jeden bit i odsyłamy resztę bez zmian.
        """
        if not 1 <= port <= nports:
            raise ValueError(f"port {port} poza zakresem 1-{nports}")
        cur = self.get("/ports_info.cgi")
        cur = cur.get("data", cur)
        form = {}
        for field, key in PORT_FIELDS:
            mask = _mask(cur.get(key))
            if mask is None:
                raise ValueError(f"brak {key} w ports_info -- nie zapisuję")
            form[field] = mask
        field = {"poe": "g_port_poe", "port": "g_port_state"}[kind]
        bit = 1 << (port - 1)
        new = form[field] | bit if on else form[field] & ~bit
        if new == form[field]:
            return False
        form[field] = new
        r = self.get("/port_state_set.cgi", form)
        if r.get("status_msg") != "ok":
            raise RuntimeError(f"switch odrzucił zmianę: {r.get('status_msg')!r}")
        return True

    def raw(self) -> dict:
        return {"sys_info": self.get("/sys_info.cgi"), "ports_info": self.get("/ports_info.cgi")}


# ---------------------------------------------------------------- parsowanie


def _num(v) -> float | None:
    m = re.search(r"-?\d+(?:\.\d+)?", str(v).replace(",", "")) if v is not None else None
    return float(m.group()) if m else None


def _mask(v) -> int | None:
    """Maski portów przychodzą jako hex w stringu ("0xffff")."""
    try:
        return int(str(v), 0)
    except (TypeError, ValueError):
        return None


def parse(raw: dict, nports: int = 16) -> dict:
    """Surowe odpowiedzi -> płaski stan publikowany do MQTT."""
    sysd = raw["sys_info"].get("data", raw["sys_info"])
    portd = raw.get("ports_info", {}).get("data", raw.get("ports_info", {}))
    poe_mask = _mask(portd.get("portPoE"))
    state_mask = _mask(portd.get("portState"))
    ports = []
    for i, row in enumerate(sysd.get("port_status", [])[:nports]):
        row = list(row)
        ports.append(
            {
                "link": str(row[0]) if row else None,
                # kolumny: link, tx, rx, loop, PoE [W]
                "poe_w": _num(row[4]) if len(row) > 4 else None,
                "poe_enabled": None if poe_mask is None else ("ON" if poe_mask >> i & 1 else "OFF"),
                "enabled": None if state_mask is None else ("ON" if state_mask >> i & 1 else "OFF"),
            }
        )
    # total_power = budżet zasilacza (135), left_power = zapas; pobór liczy sam switch (pełne waty)
    budget, left = _num(sysd.get("total_power")), _num(sysd.get("left_power"))
    used = None if budget is None or left is None else budget - left
    return {
        "mac": sysd.get("sys_MAC"),
        "name": sysd.get("sys_dev_name"),
        "model": sysd.get("model_name"),
        "firmware": sysd.get("sys_fmw_ver"),
        "uptime": _num(sysd.get("system_uptime")),
        "poe_budget": budget,
        "poe_power_left": left,
        "poe_used": used,
        "poe_budget_pct": None if used is None or not budget else round(100 * used / budget, 1),
        "ports": ports,
    }


# ---------------------------------------------------------------- MQTT discovery


def device_id(cfg: dict, state: dict) -> str:
    if cfg.get("id"):
        return cfg["id"]
    mac = re.sub(r"[^0-9a-f]", "", (state.get("mac") or "").lower())
    return f"gs1100_{mac or re.sub(r'[^0-9a-z]', '_', cfg['host'].lower())}"


def port_names(spec) -> dict[int, str]:
    """Opisy portów: "9=Kamera 1, 11=Dzwonek" (opcja add-onu) albo {"9": "Kamera 1"} / lista od portu 1."""
    if not spec:
        return {}
    if isinstance(spec, dict):
        pairs = spec.items()
    elif isinstance(spec, list):
        pairs = enumerate(spec, 1)
    else:
        pairs = re.findall(r"(\d+)\s*[=:]\s*([^,;\n]+)", str(spec))
    out = {}
    for port, name in pairs:
        name = str(name or "").strip()
        if name:
            out[int(port)] = name
    return out


def port_set(spec) -> set[int]:
    """Lista portów: "15, 16" albo [15, 16]."""
    if not spec:
        return set()
    if isinstance(spec, (list, tuple, set)):
        return {int(p) for p in spec}
    return {int(p) for p in re.findall(r"\d+", str(spec))}


def controllable(cfg: dict, control: bool, port: int, kind: str) -> bool:
    """Czy wolno przełączać dany port. Chronione: nigdy. Sam port (nie PoE): tylko gdy
    protected_ports jest ustawione -- inaczej jednym kliknięciem można odciąć uplink."""
    protected = port_set(cfg.get("protected_ports"))
    if not control or port in protected:
        return False
    return kind == "poe" or bool(protected)


def discovery_payload(dev_id: str, cfg: dict, state: dict, base: str, nports: int = 16,
                      control: bool = False) -> dict:
    cmps: dict = {}
    names = port_names(cfg.get("port_names"))

    def sensor(key, name, tpl, unit=None, dev_cla=None, **extra):
        c = {"platform": "sensor", "name": name, "unique_id": f"{dev_id}_{key}", "value_template": tpl}
        if unit:
            c.update(unit_of_measurement=unit, state_class="measurement")
        if dev_cla:
            c["device_class"] = dev_cla
        c.update(extra)
        cmps[key] = c

    sensor("poe_used", "PoE pobór", "{{ value_json.poe_used }}", "W", "power")
    sensor("poe_power_left", "PoE zapas", "{{ value_json.poe_power_left }}", "W", "power")
    sensor("poe_budget", "PoE budżet", "{{ value_json.poe_budget }}", "W", "power", entity_category="diagnostic")
    sensor("poe_budget_pct", "PoE wykorzystanie budżetu", "{{ value_json.poe_budget_pct }}", "%")
    for i in range(nports):
        n = i + 1
        port = f"Port {n} – {names[n]}" if n in names else f"Port {n}"
        sensor(f"p{n:02d}_poe_w", f"{port} PoE", f"{{{{ value_json.ports[{i}].poe_w }}}}", "W", "power")
        sensor(f"p{n:02d}_link", f"{port} link", f"{{{{ value_json.ports[{i}].link }}}}",
               entity_category="diagnostic")
        cmps[f"p{n:02d}_poe_enabled"] = {
            "platform": "binary_sensor",
            "name": f"{port} PoE włączone",
            "unique_id": f"{dev_id}_p{n:02d}_poe_enabled",
            "value_template": f"{{{{ value_json.ports[{i}].poe_enabled }}}}",
            "entity_category": "diagnostic",
        }
        # 0.2.0 tworzyło przełącznik portu jako domyślnie wyłączoną encję pod innym id -- usuń ją
        cmps[f"p{n:02d}_port_switch"] = {"platform": "switch"}
        for kind, key, field, label, extra in (
            ("poe", f"p{n:02d}_poe_switch", "poe_enabled", "zasilanie PoE", {}),
            ("port", f"p{n:02d}_if_switch", "enabled", "port włączony", {}),
        ):
            if controllable(cfg, control, n, kind):
                cmps[key] = {
                    "platform": "switch",
                    "name": f"{port} {label}",
                    "unique_id": f"{dev_id}_{key}",
                    "command_topic": f"{base}/{dev_id}/port/{n}/{kind}/set",
                    "value_template": f"{{{{ value_json.ports[{i}].{field} }}}}",
                    "state_on": "ON",
                    "state_off": "OFF",
                    "entity_category": "config",
                    **extra,
                }
            else:
                cmps[key] = {"platform": "switch"}  # sama platforma = usuń encję, jeśli istniała
    device = {
        "identifiers": [dev_id],
        "name": cfg.get("name") or state.get("name") or dev_id,
        "manufacturer": "Zyxel",
        "model": state.get("model") or "GS1100-16EP",
        "configuration_url": cfg["host"] if "://" in cfg["host"] else f"http://{cfg['host']}/",
    }
    if state.get("firmware"):
        device["sw_version"] = state["firmware"]
    if state.get("mac"):
        device["connections"] = [["mac", state["mac"].lower().replace("-", ":")]]
    return {
        "device": device,
        "origin": {"name": "gs1100-poe"},
        "state_topic": f"{base}/{dev_id}/state",
        "availability": [{"topic": f"{base}/bridge/availability"}, {"topic": f"{base}/{dev_id}/availability"}],
        "availability_mode": "all",
        "components": cmps,
    }


# ---------------------------------------------------------------- pętla


class Publisher:
    def __init__(self, mqtt_cfg: dict | None, base: str, dry: bool):
        self.base, self.client = base, None
        self.commands: queue.Queue = queue.Queue()  # (dev_id, port, kind, on)
        if dry:
            return
        import paho.mqtt.client as mqtt  # paho-mqtt >= 2.0

        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=mqtt_cfg.get("client_id", "gs1100-poe"))
        if mqtt_cfg.get("username"):
            c.username_pw_set(mqtt_cfg["username"], mqtt_cfg.get("password"))
        c.will_set(f"{base}/bridge/availability", "offline", retain=True)

        def on_connect(cl, *_):
            cl.publish(f"{base}/bridge/availability", "online", retain=True)
            cl.subscribe(f"{base}/+/port/+/+/set")

        def on_message(_cl, _ud, msg):
            m = re.fullmatch(re.escape(base) + r"/([^/]+)/port/(\d+)/(poe|port)/set", msg.topic)
            payload = msg.payload.decode(errors="replace").strip().upper()
            if m and payload in ("ON", "OFF") and not msg.retain:
                self.commands.put((m.group(1), int(m.group(2)), m.group(3), payload == "ON"))
            else:
                log.warning("pomijam komendę %s %r", msg.topic, payload)

        c.on_connect, c.on_message = on_connect, on_message
        c.connect(mqtt_cfg.get("host", "core-mosquitto"), int(mqtt_cfg.get("port", 1883)), keepalive=60)
        c.loop_start()
        self.client = c

    def pub(self, topic: str, payload, retain: bool = False):
        if not isinstance(payload, str):
            payload = json.dumps(payload, ensure_ascii=False)
        if self.client is None:
            print(f"{topic} {payload}")
        else:
            self.client.publish(topic, payload, retain=retain)

    def close(self):
        if self.client is not None:
            self.client.publish(f"{self.base}/bridge/availability", "offline", retain=True).wait_for_publish(3)
            self.client.loop_stop()
            self.client.disconnect()


class Worker:
    """Jeden switch: sesja, backoff, discovery po pierwszym udanym odczycie."""

    AUTH_BACKOFF = 600  # złe hasło: nie dobijamy panelu (ryzyko blokady)

    def __init__(self, cfg: dict, pub: Publisher, discovery_prefix: str, control: bool = False):
        self.cfg, self.pub, self.prefix, self.control = cfg, pub, discovery_prefix, control
        self.sw = GS1100(cfg["host"], cfg["password"], float(cfg.get("timeout", 10)))
        self.dev_id: str | None = cfg.get("id")
        self.discovered = False
        self.not_before = 0.0

    def poll(self) -> bool:
        if time.monotonic() < self.not_before:
            return False
        try:
            state = parse(self.sw.raw())
        except AuthError as e:
            log.error("%s: %s -- kolejna próba za %d s", self.cfg["host"], e, self.AUTH_BACKOFF)
            self.not_before = time.monotonic() + self.AUTH_BACKOFF
            return self._offline()
        except Exception as e:  # noqa: BLE001 - sieć / JSON / timeout
            log.warning("%s: odczyt nieudany: %s", self.cfg["host"], e)
            return self._offline()
        self.dev_id = self.dev_id or device_id(self.cfg, state)
        if not self.discovered:
            self.pub.pub(
                f"{self.prefix}/device/{self.dev_id}/config",
                discovery_payload(self.dev_id, self.cfg, state, self.pub.base, control=self.control),
                retain=True,
            )
            self.discovered = True
        self.pub.pub(f"{self.pub.base}/{self.dev_id}/state", state, retain=True)
        self.pub.pub(f"{self.pub.base}/{self.dev_id}/availability", "online", retain=True)
        return True

    def command(self, port: int, kind: str, on: bool) -> None:
        """Komenda z MQTT. Uprawnienia sprawdzamy tutaj, nie tylko w discovery."""
        what = f"{self.cfg['host']} port {port} {kind} -> {'ON' if on else 'OFF'}"
        if not controllable(self.cfg, self.control, port, kind):
            log.warning("odmowa: %s (sterowanie wyłączone albo port chroniony)", what)
        else:
            try:
                changed = self.sw.set_port(port, kind, on)
                log.info("%s%s", what, "" if changed else " (bez zmian)")
            except Exception as e:  # noqa: BLE001
                log.error("%s nieudane: %s", what, e)
        self.poll()  # odśwież stan w HA (także po odmowie -- przełącznik wraca na miejsce)

    def _offline(self) -> bool:
        if self.dev_id:
            self.pub.pub(f"{self.pub.base}/{self.dev_id}/availability", "offline", retain=True)
        return False


def mqtt_config(cfg: dict) -> dict:
    """MQTT z configu, a jako add-on HA: z usługi Supervisora (`services: mqtt:need`)."""
    mq = dict(cfg.get("mqtt") or {})
    token = os.environ.get("SUPERVISOR_TOKEN")
    if not mq.get("host") and token:
        req = urllib.request.Request("http://supervisor/services/mqtt", headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            mq = {**json.load(resp)["data"], **mq}
    return mq


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    for sw in cfg["switches"]:
        if "password" not in sw and sw.get("password_env"):
            sw["password"] = os.environ[sw["password_env"]]
    return cfg


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", "-c", default=os.environ.get("GS1100_CONFIG", "/data/options.json"))
    ap.add_argument("--dump", action="store_true", help="wypisz surowy JSON ze switchy i wyjdź")
    ap.add_argument("--once", action="store_true", help="jeden cykl i wyjście")
    ap.add_argument("--dry-run", "-n", action="store_true", help="bez MQTT, publikacje na stdout")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(args.config)

    if args.dump:
        rc = 0
        for sw_cfg in cfg["switches"]:
            sw = GS1100(sw_cfg["host"], sw_cfg["password"])
            try:
                print(json.dumps({"host": sw_cfg["host"], **sw.raw()}, indent=2, ensure_ascii=False))
            except Exception as e:  # noqa: BLE001
                print(f"{sw_cfg['host']}: {type(e).__name__}: {e}", file=sys.stderr)
                rc = 1
            finally:
                sw.logout()
        return rc

    base = cfg.get("base_topic", "gs1100")
    pub = Publisher(None if args.dry_run else mqtt_config(cfg), base, args.dry_run)
    control = bool(cfg.get("control"))
    workers = [Worker(s, pub, cfg.get("discovery_prefix", "homeassistant"), control) for s in cfg["switches"]]
    interval = max(5.0, float(cfg.get("interval", 30)))
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    ok = True
    try:
        while not stop.is_set():
            started = time.monotonic()
            ok = all([w.poll() for w in workers])
            if args.once:
                break
            deadline = started + max(1.0, interval - (time.monotonic() - started))
            while not stop.is_set() and time.monotonic() < deadline:
                try:
                    dev, port, kind, on = pub.commands.get(timeout=min(1.0, max(0.05, deadline - time.monotonic())))
                except queue.Empty:
                    continue
                target = [w for w in workers if w.dev_id == dev]
                if target:
                    target[0].command(port, kind, on)
                else:
                    log.warning("komenda dla nieznanego urządzenia %s", dev)
    finally:
        for w in workers:
            w._offline()
            w.sw.logout()
        pub.close()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
