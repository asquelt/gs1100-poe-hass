# Changelog

## 0.3.1
- Dodany changelog (widoczny na ekranie aktualizacji dodatku).

## 0.3.0
- Sensor mocy portu ma atrybuty `port`, `label`, `protected` — dashboard może sam nadążać za zmianami `port_names` / `protected_ports`.
- Przełączniki dostają przewidywalne identyfikatory encji (dotyczy nowo tworzonych).

## 0.2.3
- Przełącznik portu nazywa się „port włączony”.

## 0.2.2
- Przełączniki włączenia portu są od razu aktywne w HA (wcześniej domyślnie ukryte).

## 0.2.1
- Opcja `control` jest zawsze widoczna w konfiguracji dodatku.

## 0.2.0
- Opcjonalne sterowanie (`control: true`): przełączniki „zasilanie PoE” i włączenia portu.
- `protected_ports`: porty wyłączone ze sterowania (bez przełączników, komendy odrzucane).

## 0.1.2
- `port_names`: opisy portów w nazwach encji.
- Ostatni stan jest zapamiętywany w brokerze — encje mają wartość od razu po starcie.

## 0.1.1
- Dopasowanie do prawdziwych switchy: ciasteczko sesji, nagłówki przeglądarki, maski portów w hex, `total_power` jako budżet.

## 0.1.0
- Pierwsza wersja: PoE per port (W), PoE włączone, link, suma i budżet przez MQTT discovery.
