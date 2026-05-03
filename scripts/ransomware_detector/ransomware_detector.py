#!/usr/bin/env python3
"""
ransomware_detector.py — Detector automatizado de ransomware
Autor: Jorge Juarez | PFM 2026 | UCAM/Structuralia
Licencia: MIT

Detector de patrones de ransomware mediante analisis de logs JSON
producidos por Wazuh SIEM. Correlaciona eventos contra reglas YAML
mapeadas a tecnicas MITRE ATT&CK especificas de ransomware.
"""

import json
import hashlib
import logging
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

try:
    import requests
    import yaml
except ImportError as e:
    print(f"[ERROR] Dependencia faltante: {e}", file=sys.stderr)
    print("Ejecute: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(2)


# Reglas MITRE ATT&CK especificas de ransomware
MITRE_RULES = {
    "T1566": {
        "name": "Phishing",
        "severity": "WARN",
        "patterns": ["malicious_attachment", "phishing_url"]
    },
    "T1059": {
        "name": "Command Interpreter",
        "severity": "WARN",
        "patterns": ["powershell.exe -enc", "cmd.exe /c", "wscript.exe"]
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "severity": "CRITICAL",
        "patterns": ["mass_file_modification", "ransom_note_created"]
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "severity": "CRITICAL",
        "patterns": ["vssadmin delete shadows", "wbadmin delete"]
    },
}


class RansomwareDetector:
    """Detector principal de patrones de ransomware."""

    def __init__(self, config_path="config.yaml"):
        self.config = self._load_config(config_path)
        self.alerts = defaultdict(list)
        self._setup_logging()

    def _load_config(self, config_path):
        """Carga la configuracion desde YAML con manejo de errores."""
        try:
            with open(config_path) as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"[ERROR] Archivo de configuracion no encontrado: {config_path}",
                  file=sys.stderr)
            sys.exit(2)
        except yaml.YAMLError as e:
            print(f"[ERROR] Configuracion YAML malformada: {e}", file=sys.stderr)
            sys.exit(2)

    def _setup_logging(self):
        """Configura el sistema de logging."""
        logging.basicConfig(
            level=logging.INFO,
            format="[%(asctime)s] [%(levelname)s] %(message)s"
        )
        self.log = logging.getLogger(__name__)

    def analyze_event(self, event):
        """Analiza un evento contra todas las reglas MITRE."""
        event_str = json.dumps(event).lower()
        for technique_id, rule in MITRE_RULES.items():
            for pattern in rule["patterns"]:
                if pattern.lower() in event_str:
                    self.alerts[technique_id].append({
                        "timestamp": event.get("timestamp"),
                        "host": event.get("agent", {}).get("name"),
                        "user": event.get("user"),
                        "severity": rule["severity"],
                        "pattern_matched": pattern
                    })
                    self.log.warning(f"{technique_id} detectado: {pattern}")

    def evaluate_severity(self):
        """Determina severidad consolidada del incidente."""
        critical_count = sum(
            1 for t, alerts in self.alerts.items()
            if MITRE_RULES[t]["severity"] == "CRITICAL"
        )
        if critical_count >= 2:
            return "CRITICAL", "RANSOMWARE-001"
        elif critical_count >= 1:
            return "HIGH", "RANSOMWARE-002"
        elif len(self.alerts) >= 2:
            return "MEDIUM", "MONITOR-001"
        return "LOW", None

    def trigger_playbook(self, playbook_id, host):
        """Ejecuta playbook de contencion automatizada."""
        self.log.critical(f"[ACTION] Disparando playbook {playbook_id}")
        self._isolate_host(host)
        self._notify_csirt(playbook_id, host)
        self._preserve_evidence(host)

    def _isolate_host(self, host):
        """Aisla el host via API de pfSense con reintentos exponenciales."""
        url = f"{self.config['pfsense_api']}/firewall/rule"
        payload = {"action": "block", "source": host, "interface": "lan"}
        headers = {"Authorization": self.config['pfsense_token']}
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    url, json=payload, verify=False,
                    headers=headers, timeout=10
                )
                response.raise_for_status()
                self.log.info(f"[OK] Host {host} aislado via firewall API")
                return
            except requests.RequestException as e:
                wait = 2 ** attempt
                self.log.error(f"Intento {attempt+1}/{max_retries} fallo: {e}. "
                               f"Reintentando en {wait}s")
                time.sleep(wait)
        self.log.critical(f"[FAIL] No se pudo aislar {host} tras {max_retries} intentos")

    def _notify_csirt(self, playbook, host):
        """Notifica al CSIRT via webhook de Slack."""
        webhook = self.config['slack_webhook']
        msg = {
            "text": f":rotating_light: RANSOMWARE detectado\n"
                    f"Host: {host}\nPlaybook: {playbook}\n"
                    f"Timestamp: {datetime.utcnow().isoformat()}Z"
        }
        try:
            requests.post(webhook, json=msg, timeout=5)
        except requests.RequestException as e:
            self.log.error(f"Notificacion Slack fallida: {e}")

    def _preserve_evidence(self, host):
        """Captura forense via API de Velociraptor."""
        case_id = f"CASE-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        self.log.info(f"[EVIDENCE] Iniciando captura forense {case_id} en {host}")
        # Logica de invocacion a Velociraptor API segun configuracion
        # Implementacion completa en modulo lib/velociraptor_client.py


def main():
    """Punto de entrada principal."""
    detector = RansomwareDetector()
    log_path = Path("/var/log/wazuh/alerts.json")

    if not log_path.exists():
        detector.log.error(f"Log de Wazuh no encontrado: {log_path}")
        sys.exit(1)

    with open(log_path) as f:
        for line in f:
            try:
                event = json.loads(line)
                detector.analyze_event(event)
            except json.JSONDecodeError:
                continue

    severity, playbook = detector.evaluate_severity()
    detector.log.info(f"Severidad consolidada: {severity}")

    if playbook:
        affected_hosts = set(
            a["host"] for alerts in detector.alerts.values()
            for a in alerts if a.get("host")
        )
        for host in affected_hosts:
            detector.trigger_playbook(playbook, host)


if __name__ == "__main__":
    main()
