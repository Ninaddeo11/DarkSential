# syntax=docker/dockerfile:1
# Virtual lab client (IoT device / status node / attacker). Built from backend/.
# Contains only app.lab + the MQTT command contract: no backend settings, no secrets.
FROM python:3.13.15-slim-trixie
RUN apt-get update \
  && apt-get install -y --no-install-recommends iproute2 \
  && rm -rf /var/lib/apt/lists/* \
  && pip install --no-cache-dir paho-mqtt==2.1.0 \
  && useradd --system --uid 10001 --home-dir /srv lab
WORKDIR /srv
COPY app/__init__.py app/__init__.py
COPY app/lab app/lab
COPY app/mqtt/__init__.py app/mqtt/commands.py app/mqtt/
COPY --from=lab --chmod=0755 lab-entry.sh /usr/local/bin/lab-entry
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DSN_LAB_SANDBOX=1
ENTRYPOINT ["/usr/local/bin/lab-entry"]
