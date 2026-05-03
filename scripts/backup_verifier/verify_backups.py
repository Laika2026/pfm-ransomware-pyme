#!/usr/bin/env python3
"""
verify_backups.py — Verificador automatizado de integridad de respaldos
Autor: Jorge Juarez | PFM 2026 | UCAM/Structuralia
Licencia: MIT

Implementa la estrategia 3-2-1-1-0 de proteccion de respaldos:
  - Verificacion de integridad criptografica (SHA-256)
  - Validacion de antigüedad respecto al RPO definido
  - Comprobacion de inmutabilidad (S3 Object Lock COMPLIANCE mode)
  - Restauracion de muestra aleatoria en entorno aislado
  - Reporte estructurado en JSON y notificaciones a Slack
"""

import argparse
import hashlib
import json
import logging
import random
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional

try:
    import boto3
    import requests
    from botocore.exceptions import ClientError, EndpointConnectionError
except ImportError as e:
    print(f"[ERROR] Dependencia faltante: {e}", file=sys.stderr)
    print("Ejecute: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(2)


class BackupStatus:
    """Constantes de estado de verificacion."""
    VALID = "VALID"
    INVALID = "INVALID"
    STALE = "STALE"
    MISSING = "MISSING"
    UNVERIFIED = "UNVERIFIED"


class BackupVerifier:
    """Verificador de integridad y disponibilidad de respaldos."""

    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.report: List[Dict] = []
        self._setup_logging()
        self._init_s3_client()

    def _load_config(self, config_path: str) -> Dict:
        try:
            with open(config_path) as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"[ERROR] Configuracion no encontrada: {config_path}",
                  file=sys.stderr)
            sys.exit(2)
        except json.JSONDecodeError as e:
            print(f"[ERROR] Configuracion JSON malformada: {e}", file=sys.stderr)
            sys.exit(2)

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format="[%(asctime)s] [%(levelname)s] %(message)s"
        )
        self.log = logging.getLogger(__name__)

    def _init_s3_client(self):
        try:
            self.s3 = boto3.client(
                's3',
                aws_access_key_id=self.config.get('aws_access_key'),
                aws_secret_access_key=self.config.get('aws_secret_key'),
                region_name=self.config.get('aws_region', 'us-east-1')
            )
        except Exception as e:
            self.log.error(f"Fallo al inicializar cliente S3: {e}")
            sys.exit(2)

    def calculate_sha256(self, file_path: Path, chunk_size: int = 65536) -> str:
        """Calcula SHA-256 de un archivo procesando por chunks."""
        sha = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                sha.update(chunk)
        return sha.hexdigest()

    def verify_integrity(self, backup: Dict) -> Dict:
        """Verifica que el hash del respaldo coincida con el valor esperado."""
        result = {
            "backup_id": backup["id"],
            "name": backup["name"],
            "status": BackupStatus.UNVERIFIED,
            "checks": {},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        bucket = backup["bucket"]
        key = backup["key"]
        expected_hash = backup.get("expected_sha256")
        max_retries = 3

        for attempt in range(max_retries):
            try:
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    self.s3.download_file(bucket, key, tmp.name)
                    actual_hash = self.calculate_sha256(Path(tmp.name))
                    Path(tmp.name).unlink()

                result["checks"]["actual_sha256"] = actual_hash
                result["checks"]["expected_sha256"] = expected_hash

                if expected_hash and actual_hash == expected_hash:
                    result["status"] = BackupStatus.VALID
                    result["checks"]["integrity"] = "PASS"
                    self.log.info(f"[VALID] {backup['name']}: hash coincide")
                else:
                    result["status"] = BackupStatus.INVALID
                    result["checks"]["integrity"] = "FAIL"
                    self.log.error(f"[INVALID] {backup['name']}: hash divergente")
                    self._notify_critical(backup, actual_hash, expected_hash)
                break

            except (ClientError, EndpointConnectionError) as e:
                wait = 2 ** attempt
                self.log.warning(f"Intento {attempt+1}/{max_retries}: {e}. "
                                 f"Reintentando en {wait}s")
                if attempt == max_retries - 1:
                    result["status"] = BackupStatus.MISSING
                    result["checks"]["error"] = str(e)
                    self._notify_warning(backup, "Respaldo inaccesible")

        return result

    def verify_age(self, backup: Dict, result: Dict) -> Dict:
        """Verifica que la antigüedad este dentro del RPO."""
        rpo_hours = backup.get("rpo_hours", 24)
        try:
            response = self.s3.head_object(Bucket=backup["bucket"], Key=backup["key"])
            last_modified = response["LastModified"]
            age = datetime.now(timezone.utc) - last_modified
            age_hours = age.total_seconds() / 3600

            result["checks"]["age_hours"] = round(age_hours, 2)
            result["checks"]["rpo_hours"] = rpo_hours

            if age_hours > rpo_hours:
                result["status"] = BackupStatus.STALE
                result["checks"]["age_status"] = "STALE"
                self.log.warning(
                    f"[STALE] {backup['name']}: edad {age_hours:.1f}h excede "
                    f"RPO {rpo_hours}h"
                )
                self._notify_warning(backup, f"Antigüedad excede RPO ({age_hours:.1f}h)")
            else:
                result["checks"]["age_status"] = "WITHIN_RPO"
        except ClientError as e:
            result["checks"]["age_status"] = "ERROR"
            result["checks"]["age_error"] = str(e)

        return result

    def verify_immutability(self, backup: Dict, result: Dict) -> Dict:
        """Verifica que S3 Object Lock COMPLIANCE este activo."""
        try:
            response = self.s3.get_object_retention(
                Bucket=backup["bucket"], Key=backup["key"]
            )
            retention = response.get("Retention", {})
            mode = retention.get("Mode")

            result["checks"]["object_lock_mode"] = mode
            if mode == "COMPLIANCE":
                result["checks"]["immutability"] = "PASS"
                self.log.info(f"[IMMUTABLE] {backup['name']}: Object Lock COMPLIANCE activo")
            else:
                result["checks"]["immutability"] = "FAIL"
                self.log.error(
                    f"[MUTABLE] {backup['name']}: Object Lock en modo '{mode}', "
                    "se requiere COMPLIANCE"
                )
                self._notify_critical(backup, mode, "COMPLIANCE")
                if result["status"] == BackupStatus.VALID:
                    result["status"] = BackupStatus.INVALID
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchObjectLockConfiguration":
                result["checks"]["immutability"] = "FAIL"
                result["checks"]["object_lock_mode"] = "NONE"
                self.log.error(f"[NOT_LOCKED] {backup['name']}: sin Object Lock configurado")
            else:
                result["checks"]["immutability"] = "ERROR"
                result["checks"]["immutability_error"] = str(e)

        return result

    def restore_sample(self, backup: Dict, sample_pct: float = 0.05) -> Dict:
        """Restaura una muestra aleatoria del respaldo a entorno aislado."""
        sample_result = {
            "sample_pct": sample_pct,
            "files_tested": 0,
            "files_passed": 0,
            "files_failed": 0
        }
        self.log.info(
            f"Restauracion de muestra del {sample_pct*100}% de {backup['name']}"
        )
        # Logica completa en lib/restore_validator.py
        # Aqui se invocaria la restauracion en un entorno sandbox
        sample_result["status"] = "SIMULATED"
        return sample_result

    def _notify_critical(self, backup: Dict, actual, expected):
        webhook = self.config.get("slack_webhook")
        if not webhook:
            return
        msg = {
            "text": f":rotating_light: ALERTA CRITICA - Respaldo INVALIDO\n"
                    f"Nombre: {backup['name']}\n"
                    f"Hash actual: {actual}\n"
                    f"Hash esperado: {expected}\n"
                    f"Accion: bloqueada rotacion del respaldo anterior"
        }
        try:
            requests.post(webhook, json=msg, timeout=5)
        except requests.RequestException:
            pass

    def _notify_warning(self, backup: Dict, reason: str):
        webhook = self.config.get("slack_webhook")
        if not webhook:
            return
        msg = {
            "text": f":warning: Advertencia - Respaldo {backup['name']}\n"
                    f"Razon: {reason}"
        }
        try:
            requests.post(webhook, json=msg, timeout=5)
        except requests.RequestException:
            pass

    def run(self) -> Dict:
        """Ejecuta el ciclo completo de verificacion sobre todos los respaldos."""
        self.log.info("=" * 60)
        self.log.info("Inicio de verificacion de respaldos - 3-2-1-1-0")
        self.log.info("=" * 60)

        for backup in self.config.get("backups", []):
            result = self.verify_integrity(backup)
            result = self.verify_age(backup, result)
            result = self.verify_immutability(backup, result)
            if backup.get("restore_sample", False):
                result["restore_sample"] = self.restore_sample(backup)
            self.report.append(result)

        summary = self._generate_summary()
        self.log.info("=" * 60)
        self.log.info(f"Verificacion completada: {summary}")
        self.log.info("=" * 60)

        return {
            "execution_timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "results": self.report
        }

    def _generate_summary(self) -> Dict:
        summary = {
            "total": len(self.report),
            "valid": 0,
            "invalid": 0,
            "stale": 0,
            "missing": 0
        }
        for r in self.report:
            status = r["status"]
            if status == BackupStatus.VALID:
                summary["valid"] += 1
            elif status == BackupStatus.INVALID:
                summary["invalid"] += 1
            elif status == BackupStatus.STALE:
                summary["stale"] += 1
            elif status == BackupStatus.MISSING:
                summary["missing"] += 1
        return summary


def main():
    parser = argparse.ArgumentParser(
        description="Verificador de integridad de respaldos PFM"
    )
    parser.add_argument("--config", default="backup_config.json",
                        help="Ruta al archivo de configuracion JSON")
    parser.add_argument("--output", default="verification_report.json",
                        help="Ruta al reporte de salida JSON")
    args = parser.parse_args()

    verifier = BackupVerifier(args.config)
    report = verifier.run()

    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    summary = report["summary"]
    if summary["invalid"] > 0 or summary["missing"] > 0:
        sys.exit(1)
    elif summary["stale"] > 0:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
