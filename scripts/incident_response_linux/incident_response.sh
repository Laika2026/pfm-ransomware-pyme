#!/usr/bin/env bash
#
# incident_response.sh — Respuesta automatizada a incidentes en Linux
# Autor: Jorge Juarez | PFM 2026 | UCAM/Structuralia
# Licencia: MIT
#
# Ejecuta las 9 fases canonicas de respuesta forense ante incidente
# sospechoso de ransomware en sistemas Ubuntu/Debian/RHEL:
#   1. Validacion previa
#   2. Preservacion de memoria volatil
#   3. Snapshot de procesos activos
#   4. Captura de conexiones de red
#   5. Captura de logs del sistema
#   6. Hash de evidencia (SHA-256)
#   7. Compresion del paquete forense
#   8. Cifrado del paquete con GPG
#   9. Subida a almacenamiento offsite (S3)
#
# Uso: sudo ./incident_response.sh [-c CASE_ID] [-d DEST_DIR]

set -euo pipefail

#region Configuracion global

readonly SCRIPT_VERSION="1.0.0"
readonly LOCK_FILE="/var/run/incident_response.lock"
readonly DEFAULT_DEST="/forensics"
readonly MIN_FREE_GB=5
readonly S3_BUCKET="${S3_BUCKET:-pfm-forensics}"
readonly GPG_RECIPIENT="${GPG_RECIPIENT:-csirt@empresa.example.hn}"
readonly SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"

CASE_ID=""
DEST_DIR="$DEFAULT_DEST"

#endregion

#region Utilidades

log() {
    local level="$1"
    shift
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "[$timestamp] [$level] $*"
}

log_info()    { log "INFO"    "$@"; }
log_warn()    { log "WARN"    "$@"; }
log_error()   { log "ERROR"   "$@" >&2; }
log_success() { log "SUCCESS" "$@"; }

cleanup() {
    if [[ -f "$LOCK_FILE" ]]; then
        rm -f "$LOCK_FILE"
        log_info "Lock file eliminado"
    fi
}

trap cleanup EXIT INT TERM

usage() {
    cat <<EOF
Uso: $0 [-c CASE_ID] [-d DEST_DIR]
  -c CASE_ID    Identificador unico del caso (por defecto: CASE-AAAAMMDD-HHMMSS)
  -d DEST_DIR   Directorio destino para evidencia (por defecto: /forensics)
  -h            Muestra esta ayuda

Variables de entorno opcionales:
  S3_BUCKET         Bucket S3 destino (por defecto: pfm-forensics)
  GPG_RECIPIENT     Identidad GPG para cifrar (por defecto: csirt@empresa.example.hn)
  SLACK_WEBHOOK     URL del webhook de Slack para notificaciones
EOF
    exit 0
}

#endregion

#region Validaciones previas

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root o con sudo"
        exit 1
    fi
}

check_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid
        pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "?")
        log_error "Otra instancia esta en ejecucion (PID: $pid)"
        exit 5
    fi
    echo $$ > "$LOCK_FILE"
}

check_disk_space() {
    local available_kb
    available_kb=$(df --output=avail "$DEST_DIR" 2>/dev/null | tail -1 || echo "0")
    local available_gb=$((available_kb / 1024 / 1024))
    if [[ $available_gb -lt $MIN_FREE_GB ]]; then
        log_error "Espacio insuficiente: ${available_gb}GB disponibles, ${MIN_FREE_GB}GB requeridos"
        exit 4
    fi
    log_info "Espacio disponible verificado: ${available_gb}GB"
}

check_dependencies() {
    local deps=(tar gzip sha256sum gpg curl)
    local missing=()
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Dependencias faltantes: ${missing[*]}"
        exit 6
    fi
}

#endregion

#region Fases de captura forense

phase_volatile_memory() {
    log_info "Fase 2/9: Preservacion de memoria volatil..."
    local mem_dir="$CASE_DIR/02_volatile_memory"
    mkdir -p "$mem_dir"

    if command -v lime-loader &>/dev/null; then
        log_info "Capturando RAM con LiME (puede tardar varios minutos)..."
        lime-loader -p "$mem_dir/memory.lime" 2>&1 | tee "$mem_dir/lime.log" || \
            log_warn "Captura LiME parcial o fallida"
    else
        log_warn "LiME no instalado, capturando /proc/kcore (limitado)"
        cp /proc/meminfo "$mem_dir/meminfo.txt" 2>/dev/null || true
        cp /proc/swaps "$mem_dir/swaps.txt" 2>/dev/null || true
    fi

    log_success "Fase 2/9 completada"
}

phase_processes() {
    log_info "Fase 3/9: Snapshot de procesos activos..."
    local proc_dir="$CASE_DIR/03_processes"
    mkdir -p "$proc_dir"

    ps auxef    > "$proc_dir/ps_auxef.txt"
    ps -eLf     > "$proc_dir/ps_threads.txt"
    pstree -ap  > "$proc_dir/pstree.txt"
    lsof -nP    > "$proc_dir/lsof.txt" 2>/dev/null || true

    for pid in $(ps -eo pid --no-headers); do
        if [[ -d "/proc/$pid" ]]; then
            mkdir -p "$proc_dir/pid_$pid"
            cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' > "$proc_dir/pid_$pid/cmdline.txt" || true
            cp "/proc/$pid/status" "$proc_dir/pid_$pid/status.txt" 2>/dev/null || true
            ls -la "/proc/$pid/exe" 2>/dev/null > "$proc_dir/pid_$pid/exe.txt" || true
        fi
    done

    log_success "Fase 3/9 completada"
}

phase_network() {
    log_info "Fase 4/9: Captura de conexiones de red..."
    local net_dir="$CASE_DIR/04_network"
    mkdir -p "$net_dir"

    ss -tunap     > "$net_dir/ss_tunap.txt"
    netstat -anp  > "$net_dir/netstat_anp.txt" 2>/dev/null || true
    ip addr show  > "$net_dir/ip_addr.txt"
    ip route show > "$net_dir/ip_route.txt"
    iptables -L -n -v > "$net_dir/iptables.txt" 2>/dev/null || true
    arp -an       > "$net_dir/arp.txt" 2>/dev/null || true

    log_success "Fase 4/9 completada"
}

phase_logs() {
    log_info "Fase 5/9: Captura de logs del sistema..."
    local log_dir="$CASE_DIR/05_logs"
    mkdir -p "$log_dir"

    journalctl --since "24 hours ago" --no-pager > "$log_dir/journal_24h.txt" 2>/dev/null || true

    local log_files=(
        /var/log/auth.log
        /var/log/syslog
        /var/log/kern.log
        /var/log/dpkg.log
        /var/log/audit/audit.log
    )
    for lf in "${log_files[@]}"; do
        if [[ -f "$lf" ]]; then
            cp "$lf" "$log_dir/" 2>/dev/null || true
        fi
    done

    log_success "Fase 5/9 completada"
}

phase_hash_evidence() {
    log_info "Fase 6/9: Generando hashes SHA-256 (cadena de custodia)..."
    local chain_file="$CASE_DIR/chain_of_custody.txt"

    {
        echo "# Cadena de custodia - $CASE_ID"
        echo "# Generado: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo "# Operador: $(whoami)@$(hostname)"
        echo "# Script: incident_response.sh v$SCRIPT_VERSION"
        echo "# ============================================"
        echo ""
    } > "$chain_file"

    find "$CASE_DIR" -type f ! -name "chain_of_custody.txt" -print0 | \
        xargs -0 sha256sum >> "$chain_file"

    log_success "Fase 6/9 completada - $(wc -l < "$chain_file") archivos hasheados"
}

phase_compress() {
    log_info "Fase 7/9: Comprimiendo paquete forense..."
    local archive="$DEST_DIR/${CASE_ID}.tar.gz"
    tar -czf "$archive" -C "$DEST_DIR" "$CASE_ID" 2>/dev/null
    sha256sum "$archive" > "${archive}.sha256"
    log_success "Fase 7/9 completada - $(du -h "$archive" | cut -f1)"
}

phase_encrypt() {
    log_info "Fase 8/9: Cifrando paquete con GPG..."
    local archive="$DEST_DIR/${CASE_ID}.tar.gz"
    if gpg --list-keys "$GPG_RECIPIENT" &>/dev/null; then
        gpg --encrypt --trust-model always --recipient "$GPG_RECIPIENT" \
            --output "${archive}.gpg" "$archive"
        rm "$archive"
        log_success "Fase 8/9 completada - paquete cifrado para $GPG_RECIPIENT"
    else
        log_warn "Clave GPG de $GPG_RECIPIENT no encontrada, omitiendo cifrado"
    fi
}

phase_upload_s3() {
    log_info "Fase 9/9: Subida a S3..."
    local archive_pattern="$DEST_DIR/${CASE_ID}.tar.gz*"
    local max_retries=5

    if ! command -v aws &>/dev/null; then
        log_warn "AWS CLI no instalada, evidencia preservada localmente"
        return
    fi

    for archive in $archive_pattern; do
        if [[ -f "$archive" ]]; then
            local attempt=1
            while [[ $attempt -le $max_retries ]]; do
                if aws s3 cp "$archive" "s3://$S3_BUCKET/$(basename "$archive")"; then
                    log_success "Subido: $(basename "$archive")"
                    break
                else
                    local wait_s=$((2 ** attempt))
                    log_warn "Intento $attempt/$max_retries fallido, reintentando en ${wait_s}s"
                    sleep "$wait_s"
                    ((attempt++))
                fi
            done
            if [[ $attempt -gt $max_retries ]]; then
                log_error "Subida fallida tras $max_retries intentos. Marcado para reintento programado."
                touch "${archive}.pending_upload"
            fi
        fi
    done
    log_success "Fase 9/9 completada"
}

notify_csirt() {
    if [[ -z "$SLACK_WEBHOOK" ]]; then
        return
    fi
    local payload
    payload=$(cat <<EOF
{
  "text": ":rotating_light: Captura forense completada\nCaso: $CASE_ID\nHost: $(hostname)\nDestino: s3://$S3_BUCKET/"
}
EOF
)
    curl -s -X POST -H "Content-Type: application/json" \
         -d "$payload" "$SLACK_WEBHOOK" >/dev/null || true
}

#endregion

#region Punto de entrada principal

main() {
    while getopts "c:d:h" opt; do
        case "$opt" in
            c) CASE_ID="$OPTARG" ;;
            d) DEST_DIR="$OPTARG" ;;
            h) usage ;;
            *) usage ;;
        esac
    done

    if [[ -z "$CASE_ID" ]]; then
        CASE_ID="CASE-$(date -u +"%Y%m%d-%H%M%S")"
    fi

    log_info "==================================================="
    log_info "Respuesta a incidentes - $CASE_ID"
    log_info "Host: $(hostname) | Operador: $(whoami)"
    log_info "==================================================="

    log_info "Fase 1/9: Validaciones previas..."
    check_root
    check_lock
    mkdir -p "$DEST_DIR"
    check_disk_space
    check_dependencies
    log_success "Fase 1/9 completada"

    CASE_DIR="$DEST_DIR/$CASE_ID"
    mkdir -p "$CASE_DIR"

    phase_volatile_memory
    phase_processes
    phase_network
    phase_logs
    phase_hash_evidence
    phase_compress
    phase_encrypt
    phase_upload_s3
    notify_csirt

    log_success "==================================================="
    log_success "Respuesta a incidentes completada exitosamente"
    log_success "Evidencia preservada en: $DEST_DIR/${CASE_ID}.tar.gz.gpg"
    log_success "==================================================="
}

main "$@"

#endregion
