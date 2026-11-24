FROM python:3.13-alpine
RUN pip install --no-cache-dir "paho-mqtt>=2,<3"
COPY gs1100_poe.py /gs1100_poe.py
# konfiguracja: /data/options.json (opcje add-onu), MQTT: usługa Supervisora
CMD ["python3", "-u", "/gs1100_poe.py"]
