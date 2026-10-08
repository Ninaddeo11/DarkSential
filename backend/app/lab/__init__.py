"""Virtual lab: software IoT devices, a virtual status node and scripted attacks.

The lab replaces physical hardware. Each lab client runs in its own container
(``infra/docker-compose.lab.yml``) on an internal network whose only way out is
the DSN gateway, so detection, quarantine and recovery act on real (virtual)
traffic and a real nftables firewall, and nothing can leave the sandbox.

Run inside a lab container: ``python -m app.lab device|status-node|attack ...``.
Only the standard library and paho-mqtt (``lab`` extra) are imported; lab
clients never load the backend's settings or secrets.
"""
