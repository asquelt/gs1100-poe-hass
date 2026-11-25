# GS1100 PoE — Home Assistant add-on

PoE per port from Zyxel **GS1100-16EP** switches to Home Assistant via MQTT discovery:
power [W] per port, PoE enabled, link, total vs. the 135 W budget.

The switch has no SNMP/MQTT/API, so the add-on logs in to its web panel and polls
two read-only endpoints (`/sys_info.cgi`, `/ports_info.cgi`). By default it never changes
switch settings; port control is opt-in (see below).
Endpoints are undocumented and may change with firmware updates.

## Install

1. Settings → Add-ons → Add-on Store → ⋮ → Repositories → add this repository's URL.
2. Install **GS1100 PoE** (the image is built on the device).
3. Configuration: one entry per switch — `name`, `host`, `password` (web panel password) and
   optionally `port_names`, e.g. `9=Camera 1, 11=Doorbell` — entities of those ports are then
   named "Port 9 – Camera 1 PoE" etc. (the switch itself has no port labels).
4. Start. Requires the Mosquitto add-on (or another MQTT service registered with the Supervisor);
   broker credentials are taken from the Supervisor automatically.

## Port control (optional)

Set `control: true` to get switches in Home Assistant:

- **"Port N zasilanie PoE"** — PoE power on/off per port (e.g. to power-cycle a camera).
- **"Port N port włączony"** — the port itself on/off. Created only when `protected_ports`
  is set.

`protected_ports` (per switch, e.g. `15, 16`) lists ports that must never be switched:
they get no switch entities and commands for them are refused. Put the uplink and the port
Home Assistant is reached through there — disabling the uplink port cuts the switch off
and takes a visit (or a factory reset) to undo.

The switch stores all ports in one request, so a change reads the current settings, flips
one bit and writes the rest back unchanged.

The panel allows one session at a time: while the add-on runs, logging in to the switch's
web UI is refused (HTTP 403) — stop the add-on first.

## Standalone

    pip install "paho-mqtt>=2"
    cp config.example.json config.json   # hosts, passwords, broker
    python3 gs1100_poe/gs1100_poe.py -c config.json --dump     # raw JSON from the switch
    python3 gs1100_poe/gs1100_poe.py -c config.json            # poll loop

## Tests

    python3 -m unittest discover -s tests -v
