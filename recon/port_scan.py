import socket
import logging

logger = logging.getLogger("SentinelX")

COMMON_PORTS = [21, 22, 80, 443, 3306, 8080, 8443]

def scan_ports(host):
    open_ports = []

    logger.info(f"Port scanning {host}")

    for port in COMMON_PORTS:
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((host, port))
            open_ports.append(port)
            sock.close()
        except:
            pass

    return open_ports
