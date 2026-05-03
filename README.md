# Plan de Respuesta a Incidentes de Ransomware para PYME Hondureña

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Academic](https://img.shields.io/badge/Status-Academic--PFM-blue.svg)](#)
[![Lang: ES](https://img.shields.io/badge/Lang-Espa%C3%B1ol-red.svg)](#)

Repositorio público de código y materiales asociados al **Trabajo Final de Máster en Ciberseguridad Corporativa** de la Universidad Católica de Murcia (UCAM) en colaboración con Structuralia, promoción 2026.

---

## Acerca del proyecto

Este repositorio contiene los cuatro scripts de automatización desarrollados como componente técnico del Plan de Respuesta a Incidentes de Ransomware diseñado para una PYME comercial hondureña tipológica. El proyecto se enmarca como propuesta metodológica de naturaleza propositiva, conforme al alcance académico declarado en el documento del Trabajo Final de Máster.

**Autor:** Jorge Juárez
**Programa:** Máster en Ciberseguridad Corporativa, UCAM / Structuralia
**Promoción:** 2026
**Tutor académico:** [Asignado por el programa]
**Licencia:** MIT (ver archivo [LICENSE](LICENSE))

---

## Estructura del repositorio
pfm-ransomware-pyme/
├── README.md                              # Este archivo
├── LICENSE                                # Licencia MIT
├── CITATION.cff                           # Metadatos de citación académica
├── INTEGRITY.sha256                       # Hashes SHA-256 de scripts
├── .gitignore                             # Patrones ignorados por Git
└── scripts/
├── ransomware_detector/
│   └── ransomware_detector.py         # SCR-001: Detector Python
├── windows_hardening/
│   └── Harden-Workstation.ps1         # SCR-002: Hardening PowerShell
├── incident_response_linux/
│   └── incident_response.sh           # SCR-003: Respuesta Bash
└── backup_verifier/
└── verify_backups.py              # SCR-004: Verificador respaldos
---

## Catálogo de scripts

| ID | Archivo | Lenguaje | Propósito |
|----|---------|----------|-----------|
| SCR-001 | `ransomware_detector.py` | Python 3.9+ | Detección automatizada de ransomware mediante reglas MITRE ATT&CK aplicadas sobre logs Wazuh |
| SCR-002 | `Harden-Workstation.ps1` | PowerShell 5.1+ | Endurecimiento de estaciones Windows 10/11 con tres perfiles graduados (Permissive, Standard, Strict) |
| SCR-003 | `incident_response.sh` | Bash 4.4+ | Respuesta forense automatizada en Linux con 9 fases de captura y cadena de custodia SHA-256 |
| SCR-004 | `verify_backups.py` | Python 3.9+ | Verificación de integridad de respaldos bajo estrategia 3-2-1-1-0 con S3 Object Lock |

---

## Reproducibilidad académica

### Clonado del repositorio

```bash
git clone https://github.com/Laika2026/pfm-ransomware-pyme.git
cd pfm-ransomware-pyme
```

### Verificación de integridad

```bash
# Linux / macOS
sha256sum -c INTEGRITY.sha256

# Windows PowerShell
Get-FileHash scripts\**\*.py, scripts\**\*.ps1, scripts\**\*.sh -Algorithm SHA256
```

### Validación funcional

Los 24 casos de prueba del diseño funcional de los cuatro scripts están consignados en la **Tabla 18 «Matriz consolidada de casos de prueba»** del documento del Trabajo Final de Máster (Anexo A.1). Los identificadores de prueba siguen el formato `T-{ID-SCRIPT}-{N}`, donde:

- `T-001-XX` corresponde a los seis casos de SCR-001
- `T-002-XX` corresponde a los seis casos de SCR-002
- `T-003-XX` corresponde a los seis casos de SCR-003
- `T-004-XX` corresponde a los seis casos de SCR-004

---

## Naturaleza académica del trabajo

Conforme a la modalidad propositiva del presente Trabajo Final de Máster, los scripts y su matriz de pruebas representan la **validación del diseño funcional** del Plan de Respuesta a Incidentes propuesto. La ejecución empírica con cepas reales de ransomware en entorno productivo o de laboratorio físico se enmarca como **primera línea futura de investigación**, conforme se detalla en la sección 9.2 del documento del Trabajo Final de Máster.

Esta declaración explícita preserva la integridad académica del trabajo y delimita con precisión el alcance contributivo del repositorio dentro del marco del programa de Máster.

---

## Cita académica

Si utiliza este software o cita su contenido, por favor consulte el archivo [`CITATION.cff`](CITATION.cff) en la raíz del repositorio para los metadatos de citación en formato Citation File Format (estándar GitHub para citación académica).

---

## Licencia

Este proyecto se distribuye bajo licencia MIT. Vea el archivo [LICENSE](LICENSE) para los términos completos.

---

## Contacto

Para consultas académicas relativas a este Trabajo Final de Máster, dirigirse al autor a través de las vías oficiales del programa de Máster en Ciberseguridad Corporativa de UCAM / Structuralia.

---

*Repositorio creado en mayo 2026 como entregable académico del Trabajo Final de Máster en Ciberseguridad Corporativa, UCAM / Structuralia.*
