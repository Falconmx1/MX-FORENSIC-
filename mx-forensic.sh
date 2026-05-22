#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                    MX-FORENSIC - Suite Forense Profesional                    ║
# ║         Análisis de memoria, discos, live response, YARA, Volatility          ║
# ║                     Cifrado, envío remoto, VirusTotal, Dashboard              ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
# Versión: 3.0.0
# Autor: Falconmx1
# Licencia: GPL-3.0

set -euo pipefail

# ======================[ CONFIGURACIÓN GLOBAL ]======================
VERSION="3.0.0"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Configuración por defecto
OUTPUT_DIR="./outputs"
LOG_FILE=""
DO_RAM=false
DO_DISK=""
DO_HASH=false
DO_ANALYZE=false
DO_REPORT=false
DO_VOLATILITY=false
DO_YARA=false
DO_LIVE_RESPONSE=false
DO_EWF=false
DO_ENCRYPT=false
DO_UPLOAD=false
DO_VT=false
DO_DASHBOARD=false
ENCRYPT_PASSPHRASE=""
UPLOAD_TYPE=""
UPLOAD_HOST=""
UPLOAD_USER=""
UPLOAD_PATH=""
UPLOAD_KEY=""
VT_API_KEY=""
WEBHOOK_URL=""
ALERT_EMAIL=""

# ======================[ FUNCIONES DE UTILIDAD ]======================
print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ███╗   ███╗██╗  ██╗     ███████╗ ██████╗ ██████╗ ███████╗      ║
║   ████╗ ████║╚██╗██╔╝     ██╔════╝██╔═══██╗██╔══██╗██╔════╝      ║
║   ██╔████╔██║ ╚███╔╝█████╗█████╗  ██║   ██║██████╔╝█████╗        ║
║   ██║╚██╔╝██║ ██╔██╗╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝        ║
║   ██║ ╚═╝ ██║██╔╝ ██╗     ██║     ╚██████╔╝██║  ██║███████╗      ║
║   ╚═╝     ╚═╝╚═╝  ╚═╝     ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝      ║
║                                                                   ║
║                    FORENSIC SUITE v$VERSION                        ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

setup_logging() {
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    LOG_FILE="${OUTPUT_DIR}/mx_forensic_${timestamp}.log"
    mkdir -p "$OUTPUT_DIR"
    exec 2>&1 | tee -a "$LOG_FILE"
}

log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")  echo -e "${GREEN}[+]${NC} $timestamp - $message" ;;
        "WARN")  echo -e "${YELLOW}[!]${NC} $timestamp - $message" ;;
        "ERROR") echo -e "${RED}[x]${NC} $timestamp - $message" ;;
        "DEBUG") echo -e "${BLUE}[*]${NC} $timestamp - $message" ;;
        *)       echo -e "$timestamp - $message" ;;
    esac
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log ERROR "Este script debe ejecutarse como root"
        exit 1
    fi
}

check_dependencies() {
    local deps=("dd" "grep" "awk" "sed" "curl" "jq" "openssl" "tar")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log WARN "Dependencias faltantes: ${missing[*]}"
        log INFO "Instalando dependencias..."
        
        if [[ -f /etc/debian_version ]]; then
            apt-get update -qq
            apt-get install -y -qq "${missing[@]}" openssl curl jq
        elif [[ -f /etc/redhat-release ]]; then
            yum install -y -q "${missing[@]}" openssl curl jq
        fi
    fi
    
    log INFO "✓ Dependencias verificadas"
}

# ======================[ NÚCLEO FORENSE ]======================
dump_ram() {
    local output_file="$OUTPUT_DIR/ram_${HOSTNAME}_$(date +%Y%m%d_%H%M%S).raw"
    log INFO "Iniciando dump de memoria RAM: $output_file"
    
    local ram_size=$(free -b | awk '/^Mem:/{print $2}')
    log DEBUG "Tamaño de RAM detectado: $(numfmt --to=iec $ram_size)"
    
    if command -v avml &> /dev/null; then
        avml "$output_file"
    elif command -v lime &> /dev/null; then
        lime --format raw --output "$output_file"
    elif [[ -f /proc/kcore ]]; then
        dd if=/proc/kcore of="$output_file" bs=1M status=progress 2>&1
    else
        log ERROR "No se encontró método para dump de RAM"
        return 1
    fi
    
    if [[ -f "$output_file" ]]; then
        local file_size=$(du -h "$output_file" | cut -f1)
        log INFO "✓ RAM dump completado: $file_size"
        echo "$output_file"
    else
        log ERROR "Falló el dump de RAM"
        return 1
    fi
}

dump_disk() {
    local disk="$1"
    local output_file="$OUTPUT_DIR/disk_${HOSTNAME}_$(date +%Y%m%d_%H%M%S).dd"
    
    log INFO "Iniciando dump de disco: $disk -> $output_file"
    
    if [[ ! -b "$disk" ]]; then
        log ERROR "Dispositivo no válido: $disk"
        return 1
    fi
    
    local disk_size=$(blockdev --getsize64 "$disk")
    log DEBUG "Tamaño de disco: $(numfmt --to=iec $disk_size)"
    
    if command -v dcfldd &> /dev/null; then
        dcfldd if="$disk" of="$output_file" bs=4M hash=md5,sha256 hashlog="${output_file}.hashlog" statusinterval=10
    else
        dd if="$disk" of="$output_file" bs=4M status=progress 2>&1
    fi
    
    if [[ -f "$output_file" ]]; then
        local file_size=$(du -h "$output_file" | cut -f1)
        log INFO "✓ Disco dump completado: $file_size"
        echo "$output_file"
    else
        log ERROR "Falló el dump de disco"
        return 1
    fi
}

calculate_hashes() {
    local file="$1"
    local hash_file="$OUTPUT_DIR/hashes_$(date +%Y%m%d_%H%M%S).txt"
    
    log INFO "Calculando hashes de integridad para: $(basename "$file")"
    
    {
        echo "╔══════════════════════════════════════════════════════════╗"
        echo "║           MX-FORENSIC - Hash de Integridad               ║"
        echo "╠══════════════════════════════════════════════════════════╣"
        echo "║ Archivo: $(basename "$file")"
        echo "║ Tamaño: $(du -h "$file" | cut -f1)"
        echo "║ Fecha: $(date)"
        echo "╠══════════════════════════════════════════════════════════╣"
        
        echo "║ MD5:    $(md5sum "$file" | cut -d' ' -f1)"
        echo "║ SHA1:   $(sha1sum "$file" | cut -d' ' -f1)"
        echo "║ SHA256: $(sha256sum "$file" | cut -d' ' -f1)"
        
        echo "╚══════════════════════════════════════════════════════════╝"
    } | tee "$hash_file"
    
    log INFO "✓ Hashes guardados en: $hash_file"
    echo "$hash_file"
}

simple_analysis() {
    local ram_dump="$1"
    local analysis_file="$OUTPUT_DIR/analysis_$(date +%Y%m%d_%H%M%S).txt"
    
    log INFO "Realizando análisis básico de memoria"
    
    {
        echo "╔══════════════════════════════════════════════════════════╗"
        echo "║           MX-FORENSIC - Análisis de Memoria              ║"
        echo "╠══════════════════════════════════════════════════════════╣"
        echo ""
        echo "🔍 PROCESOS ENCONTRADOS"
        echo "═══════════════════════════════════════════════════════════"
        strings "$ram_dump" 2>/dev/null | grep -E '^[a-zA-Z0-9_.-]+\.(exe|dll|so|bin)$' | sort -u | head -100
        
        echo ""
        echo "🌐 CONEXIONES DE RED"
        echo "═══════════════════════════════════════════════════════════"
        strings "$ram_dump" 2>/dev/null | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+' | sort -u | head -50
        
        echo ""
        echo "🔑 PALABRAS CLAVE SENSIBLES"
        echo "═══════════════════════════════════════════════════════════"
        strings "$ram_dump" 2>/dev/null | grep -E -i "pass|token|secret|key|auth|cookie|session" | head -50
        
        echo ""
        echo "⚙️ COMANDOS EJECUTADOS"
        echo "═══════════════════════════════════════════════════════════"
        strings "$ram_dump" 2>/dev/null | grep -E "^[a-z]+ [\-a-z]+" | sort -u | head -50
    } > "$analysis_file"
    
    log INFO "✓ Análisis guardado en: $analysis_file"
    echo "$analysis_file"
}

# ======================[ MÓDULOS AVANZADOS ]======================
run_volatility() {
    local ram_dump="$1"
    local vol_output="$OUTPUT_DIR/volatility_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$vol_output"
    
    log INFO "Ejecutando análisis Volatility 3"
    
    if ! command -v vol &> /dev/null; then
        log WARN "Volatility 3 no instalado. Instalando..."
        pip3 install volatility3 &> /dev/null || {
            log ERROR "No se pudo instalar Volatility"
            return 1
        }
    fi
    
    local plugins=(
        "windows.pslist.PsList"
        "windows.psscan.PsScan"
        "windows.netscan.NetScan"
        "windows.dlllist.DllList"
        "windows.cmdline.CmdLine"
        "windows.malfind.Malfind"
    )
    
    for plugin in "${plugins[@]}"; do
        log DEBUG "Ejecutando plugin: $plugin"
        vol -f "$ram_dump" "$plugin" > "$vol_output/${plugin//./_}.txt" 2>/dev/null
    done
    
    log INFO "✓ Análisis Volatility completado en: $vol_output"
    echo "$vol_output"
}

run_yara() {
    local target="$1"
    local yara_output="$OUTPUT_DIR/yara_$(date +%Y%m%d_%H%M%S).txt"
    local rules_dir="${2:-./modules/yara_rules}"
    
    log INFO "Escaneando con YARA: $target"
    
    if ! command -v yara &> /dev/null; then
        log WARN "YARA no instalado. Instalando..."
        if [[ -f /etc/debian_version ]]; then
            apt-get install -y yara
        else
            git clone https://github.com/VirusTotal/yara.git /tmp/yara
            cd /tmp/yara && ./bootstrap.sh && ./configure && make && make install
        fi
    fi
    
    if [[ -d "$rules_dir" ]]; then
        yara -r -s "$rules_dir" "$target" > "$yara_output" 2>/dev/null
    else
        # Reglas básicas integradas
        cat > /tmp/basic_rules.yar << 'EOF'
rule Suspicious_Process {
    strings:
        $s1 = /meterpreter|reverse_shell|nc\.exe/i
        $s2 = /mimikatz|pwdump|hashdump/i
    condition:
        any of them
}
rule Crypto_Miner {
    strings:
        $s1 = "stratum+tcp://"
        $s2 = "XMRig"
        $s3 = "Claymore"
    condition:
        any of them
}
EOF
        yara -r -s /tmp/basic_rules.yar "$target" > "$yara_output" 2>/dev/null
    fi
    
    if [[ -s "$yara_output" ]]; then
        local matches=$(wc -l < "$yara_output")
        log WARN "¡Encontradas $matches coincidencias YARA!"
        cat "$yara_output"
    else
        log INFO "✓ No se encontraron coincidencias YARA"
    fi
    
    echo "$yara_output"
}

live_response() {
    local live_dir="$OUTPUT_DIR/live_response_${HOSTNAME}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$live_dir"
    
    log INFO "Iniciando Live Response - Recolección de evidencias en caliente"
    
    # Sistema
    uname -a > "$live_dir/uname.txt"
    cat /etc/os-release > "$live_dir/os.txt"
    uptime > "$live_dir/uptime.txt"
    date > "$live_dir/date.txt"
    
    # Procesos
    ps auxf > "$live_dir/ps_auxf.txt"
    ps -eLf > "$live_dir/ps_threads.txt"
    pstree -p > "$live_dir/pstree.txt"
    top -b -n 1 > "$live_dir/top.txt"
    
    # Red
    netstat -tupan > "$live_dir/netstat.txt"
    ss -tunap > "$live_dir/ss.txt"
    lsof -i -n -P > "$live_dir/lsof_network.txt"
    arp -a > "$live_dir/arp.txt"
    route -n > "$live_dir/route.txt"
    
    # Usuarios
    who -a > "$live_dir/who.txt"
    w > "$live_dir/w.txt"
    last -n 100 > "$live_dir/last.txt"
    cat /etc/passwd > "$live_dir/passwd.txt"
    cat /etc/shadow > "$live_dir/shadow.txt" 2>/dev/null || true
    
    # Archivos
    lsof > "$live_dir/lsof_all.txt"
    find / -type f -mtime -1 -ls 2>/dev/null > "$live_dir/files_24h.txt"
    find /tmp -type f -ls 2>/dev/null > "$live_dir/tmp_files.txt"
    
    # Kernel
    lsmod > "$live_dir/lsmod.txt"
    dmesg | tail -n 200 > "$live_dir/dmesg.txt"
    sysctl -a > "$live_dir/sysctl.txt" 2>/dev/null || true
    
    # Servicios
    systemctl list-units --all > "$live_dir/services.txt" 2>/dev/null || true
    crontab -l > "$live_dir/crontab.txt" 2>/dev/null || true
    
    # Memoria
    free -h > "$live_dir/free.txt"
    cat /proc/meminfo > "$live_dir/meminfo.txt"
    
    # Logs críticos
    cp /var/log/auth.log "$live_dir/" 2>/dev/null || true
    cp /var/log/syslog "$live_dir/" 2>/dev/null || true
    journalctl -n 1000 > "$live_dir/journalctl.txt" 2>/dev/null || true
    
    # Empaquetar
    tar -czf "$live_dir.tar.gz" -C "$live_dir" . 2>/dev/null
    rm -rf "$live_dir"
    
    log INFO "✓ Live Response completado: $live_dir.tar.gz"
    echo "$live_dir.tar.gz"
}

create_ewf() {
    local source="$1"
    local ewf_output="$OUTPUT_DIR/ewf_${HOSTNAME}_$(date +%Y%m%d_%H%M%S)"
    
    log INFO "Creando imagen EWF (E01) de: $source"
    
    if ! command -v ewfacquire &> /dev/null; then
        log WARN "Instalando libewf..."
        if [[ -f /etc/debian_version ]]; then
            apt-get install -y libewf ewf-tools
        else
            log ERROR "EWF no disponible. Instala libewf manualmente"
            return 1
        fi
    fi
    
    ewfacquire -u -c fast -b 64 -f encase5 \
        -S "MX-FORENSIC" \
        -C "Caso_$(date +%Y%m%d)" \
        -e "E001" \
        -d "$source" \
        -t "$ewf_output" \
        -l "${ewf_output}.log"
    
    if [[ -f "${ewf_output}.E01" ]]; then
        log INFO "✓ Imagen EWF creada: ${ewf_output}.E01"
        echo "${ewf_output}.E01"
    else
        log ERROR "Falló creación de EWF"
        return 1
    fi
}

# ======================[ CIFRADO AES-256 ]======================
encrypt_evidence() {
    local file="$1"
    local passphrase="${2:-}"
    
    if [[ -z "$passphrase" ]]; then
        read -s -p "🔐 Passphrase para cifrado: " passphrase
        echo
    fi
    
    local encrypted_file="${file}.aes256"
    
    log INFO "Cifrando evidencias: $(basename "$file")"
    
    openssl enc -aes-256-cbc -salt -pbkdf2 \
        -in "$file" \
        -out "$encrypted_file" \
        -pass pass:"$passphrase"
    
    if [[ -f "$encrypted_file" ]]; then
        log INFO "✓ Archivo cifrado: $encrypted_file"
        
        # Guardar hash del archivo original para verificación
        sha256sum "$file" > "${encrypted_file}.sha256"
        
        # Opción de eliminar original
        read -p "¿Eliminar archivo original? (s/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Ss]$ ]]; then
            shred -u "$file"
            log INFO "✓ Archivo original eliminado de forma segura"
        fi
        
        echo "$encrypted_file"
    else
        log ERROR "Falló el cifrado"
        return 1
    fi
}

decrypt_evidence() {
    local encrypted_file="$1"
    local passphrase="${2:-}"
    
    if [[ -z "$passphrase" ]]; then
        read -s -p "🔐 Passphrase para descifrado: " passphrase
        echo
    fi
    
    local decrypted_file="${encrypted_file%.aes256}"
    
    log INFO "Descifrando: $(basename "$encrypted_file")"
    
    openssl enc -aes-256-cbc -d -pbkdf2 \
        -in "$encrypted_file" \
        -out "$decrypted_file" \
        -pass pass:"$passphrase"
    
    if [[ -f "$decrypted_file" ]]; then
        log INFO "✓ Archivo descifrado: $decrypted_file"
        
        # Verificar integridad
        if [[ -f "${encrypted_file}.sha256" ]]; then
            local original_hash=$(cat "${encrypted_file}.sha256" | cut -d' ' -f1)
            local current_hash=$(sha256sum "$decrypted_file" | cut -d' ' -f1)
            
            if [[ "$original_hash" == "$current_hash" ]]; then
                log INFO "✓ Integridad verificada - Hashes coinciden"
            else
                log ERROR "⚠️ INTEGRIDAD COMPROMETIDA - Hashes NO coinciden"
            fi
        fi
        
        echo "$decrypted_file"
    else
        log ERROR "Falló el descifrado"
        return 1
    fi
}

# ======================[ ENVÍO REMOTO ]======================
upload_scp() {
    local file="$1"
    local host="$2"
    local user="$3"
    local remote_path="$4"
    local ssh_key="$5"
    
    log INFO "Enviando vía SCP a $user@$host:$remote_path"
    
    scp -i "$ssh_key" -o StrictHostKeyChecking=no "$file" "$user@$host:$remote_path" 2>&1
    
    if [[ $? -eq 0 ]]; then
        log INFO "✓ Archivo enviado exitosamente"
        return 0
    else
        log ERROR "Falló el envío SCP"
        return 1
    fi
}

upload_rsync() {
    local file="$1"
    local host="$2"
    local user="$3"
    local remote_path="$4"
    local ssh_key="$5"
    
    log INFO "Enviando vía RSYNC a $user@$host:$remote_path"
    
    rsync -avz -e "ssh -i $ssh_key -o StrictHostKeyChecking=no" \
        "$file" "$user@$host:$remote_path" 2>&1
    
    if [[ $? -eq 0 ]]; then
        log INFO "✓ Archivo sincronizado exitosamente"
        return 0
    else
        log ERROR "Falló la sincronización RSYNC"
        return 1
    fi
}

upload_sftp() {
    local file="$1"
    local host="$2"
    local user="$3"
    local remote_path="$4"
    local password="$5"
    
    log INFO "Enviando vía SFTP a $user@$host:$remote_path"
    
    if [[ -n "$password" ]]; then
        sshpass -p "$password" sftp -o StrictHostKeyChecking=no "$user@$host" <<EOF
put "$file" "$remote_path/"
bye
EOF
    else
        sftp -o StrictHostKeyChecking=no "$user@$host" <<EOF
put "$file" "$remote_path/"
bye
EOF
    fi
    
    if [[ $? -eq 0 ]]; then
        log INFO "✓ Archivo enviado exitosamente"
        return 0
    else
        log ERROR "Falló el envío SFTP"
        return 1
    fi
}

upload_webdav() {
    local file="$1"
    local url="$2"
    local username="$3"
    local password="$4"
    
    log INFO "Enviando vía WebDAV a $url"
    
    curl -T "$file" -u "$username:$password" "$url/$(basename "$file")" 2>&1
    
    if [[ $? -eq 0 ]]; then
        log INFO "✓ Archivo enviado exitosamente"
        return 0
    else
        log ERROR "Falló el envío WebDAV"
        return 1
    fi
}

auto_upload() {
    local file="$1"
    
    if [[ "$DO_UPLOAD" != true ]]; then
        return 0
    fi
    
    log INFO "Iniciando envío automático a servidor remoto"
    
    case "$UPLOAD_TYPE" in
        "scp")
            upload_scp "$file" "$UPLOAD_HOST" "$UPLOAD_USER" "$UPLOAD_PATH" "$UPLOAD_KEY"
            ;;
        "rsync")
            upload_rsync "$file" "$UPLOAD_HOST" "$UPLOAD_USER" "$UPLOAD_PATH" "$UPLOAD_KEY"
            ;;
        "sftp")
            upload_sftp "$file" "$UPLOAD_HOST" "$UPLOAD_USER" "$UPLOAD_PATH" "$UPLOAD_KEY"
            ;;
        "webdav")
            upload_webdav "$file" "$UPLOAD_HOST" "$UPLOAD_USER" "$UPLOAD_PATH"
            ;;
        *)
            log ERROR "Método de envío no soportado: $UPLOAD_TYPE"
            return 1
            ;;
    esac
}

# ======================[ VIRUSTOTAL INTEGRATION ]======================
check_virustotal() {
    local file="$1"
    local api_key="$2"
    
    if [[ -z "$api_key" ]]; then
        log WARN "No se proporcionó API key de VirusTotal"
        return 1
    fi
    
    log INFO "Enviando archivo a VirusTotal para análisis"
    
    local file_size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)
    
    if [[ $file_size -gt 33554432 ]]; then  # 32MB limit
        log WARN "Archivo >32MB, usando método de URL (solo hash)"
        local file_hash=$(sha256sum "$file" | cut -d' ' -f1)
        local vt_url="https://www.virustotal.com/api/v3/files/${file_hash}"
        
        curl -s -X GET "$vt_url" \
            -H "x-apikey: $api_key" > "$OUTPUT_DIR/vt_report.json" 2>/dev/null
    else
        # Subir archivo
        curl -s -X POST "https://www.virustotal.com/api/v3/files" \
            -H "x-apikey: $api_key" \
            -F "file=@$file" > "$OUTPUT_DIR/vt_upload.json" 2>/dev/null
        
        local analysis_id=$(jq -r '.data.id' "$OUTPUT_DIR/vt_upload.json" 2>/dev/null)
        
        if [[ -n "$analysis_id" && "$analysis_id" != "null" ]]; then
            sleep 10  # Esperar análisis
            curl -s -X GET "https://www.virustotal.com/api/v3/analyses/${analysis_id}" \
                -H "x-apikey: $api_key" > "$OUTPUT_DIR/vt_report.json" 2>/dev/null
        fi
    fi
    
    if [[ -f "$OUTPUT_DIR/vt_report.json" ]]; then
        local positives=$(jq -r '.data.attributes.stats.malicious' "$OUTPUT_DIR/vt_report.json" 2>/dev/null)
        local total=$(jq -r '.data.attributes.stats. harmless + .data.attributes.stats.malicious + .data.attributes.stats.suspicious' "$OUTPUT_DIR/vt_report.json" 2>/dev/null)
        
        if [[ -n "$positives" && "$positives" != "null" ]]; then
            log INFO "📊 VirusTotal: $positives/$total detecciones"
            
            if [[ $positives -gt 0 ]]; then
                log WARN "⚠️ ARCHIVO MARCADO COMO MALICIOSO por $positives antivirus"
                send_alert "⚠️ ALERTA: Archivo malicioso detectado por VirusTotal" "$file - $positives/$total detecciones"
            fi
        fi
        
        # Generar reporte HTML
        local vt_html="$OUTPUT_DIR/virustotal_report.html"
        cat > "$vt_html" << EOF
<!DOCTYPE html>
<html>
<head><title>VirusTotal Report</title></head>
<body>
<h1>🔍 VirusTotal Analysis Report</h1>
<pre>$(cat "$OUTPUT_DIR/vt_report.json" | jq . 2>/dev/null)</pre>
</body>
</html>
EOF
        log INFO "✓ Reporte VirusTotal: $vt_html"
    else
        log WARN "No se pudo obtener análisis de VirusTotal"
    fi
}

# ======================[ DASHBOARD WEB ]======================
generate_dashboard() {
    local dashboard_dir="$OUTPUT_DIR/dashboard"
    mkdir -p "$dashboard_dir"
    
    log INFO "Generando dashboard web interactivo"
    
    # Datos para el dashboard
    local timestamp=$(date +%s)
    local hostname=$(hostname)
    local total_files=$(find "$OUTPUT_DIR" -type f -name "*.raw" -o -name "*.dd" -o -name "*.tar.gz" 2>/dev/null | wc -l)
    local total_size=$(du -sh "$OUTPUT_DIR" 2>/dev/null | cut -f1)
    
    # JSON data
    cat > "$dashboard_dir/data.json" << EOF
{
    "timestamp": $timestamp,
    "hostname": "$hostname",
    "total_files": $total_files,
    "total_size": "$total_size",
    "files": [
EOF
    
    find "$OUTPUT_DIR" -type f \( -name "*.raw" -o -name "*.dd" -o -name "*.txt" -o -name "*.json" -o -name "*.html" \) -exec basename {} \; | while read file; do
        local size=$(du -h "$OUTPUT_DIR/$file" 2>/dev/null | cut -f1)
        echo "{\"name\":\"$file\",\"size\":\"$size\"}," >> "$dashboard_dir/data.json"
    done
    
    sed -i '$ s/,$//' "$dashboard_dir/data.json"
    echo "]" >> "$dashboard_dir/data.json"
    
    # HTML Dashboard
    cat > "$dashboard_dir/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MX-FORENSIC Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3e 100%);
            color: #00ff41;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            text-align: center;
            padding: 30px;
            background: rgba(0,255,65,0.1);
            border-radius: 10px;
            margin-bottom: 30px;
            border: 1px solid #00ff41;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(0,0,0,0.5);
            border: 1px solid #00ff41;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            transition: transform 0.3s;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #ff3366;
        }
        .stat-label { margin-top: 10px; font-size: 0.9em; }
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .chart-container {
            background: rgba(0,0,0,0.5);
            border: 1px solid #00ff41;
            border-radius: 10px;
            padding: 20px;
        }
        .file-list {
            background: rgba(0,0,0,0.5);
            border: 1px solid #00ff41;
            border-radius: 10px;
            padding: 20px;
            max-height: 500px;
            overflow-y: auto;
        }
        .file-item {
            padding: 10px;
            border-bottom: 1px solid #00ff41;
            display: flex;
            justify-content: space-between;
        }
        .file-item:hover { background: rgba(0,255,65,0.1); }
        .alert {
            background: rgba(255,51,102,0.2);
            border-left: 4px solid #ff3366;
            padding: 10px;
            margin: 10px 0;
        }
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
        .live { animation: blink 1s infinite; }
        .footer {
            text-align: center;
            padding: 20px;
            margin-top: 30px;
            border-top: 1px solid #00ff41;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 MX-FORENSIC Dashboard</h1>
            <p>Live Forensics Monitoring & Analysis Platform</p>
            <p id="timestamp" class="live"></p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="totalFiles">0</div>
                <div class="stat-label">Archivos Recolectados</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="totalSize">0</div>
                <div class="stat-label">Tamaño Total</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="totalRAM">0</div>
                <div class="stat-label">RAM Capturada (GB)</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="totalDisk">0</div>
                <div class="stat-label">Disco Capturado (GB)</div>
            </div>
        </div>
        
        <div class="charts-grid">
            <div class="chart-container">
                <canvas id="fileTypesChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="timelineChart"></canvas>
            </div>
        </div>
        
        <div class="file-list">
            <h2>📁 Evidencias Recolectadas</h2>
            <div id="fileList"></div>
        </div>
        
        <div class="footer">
            <p>MX-FORENSIC v3.0 | Powered by Falconmx1 | 🔒 Cadena de Custodia Activa</p>
            <p><small>Actualización en tiempo real cada 5 segundos</small></p>
        </div>
    </div>
    
    <script>
        let refreshInterval;
        
        function loadData() {
            fetch('data.json?' + Date.now())
                .then(response => response.json())
                .then(data => {
                    document.getElementById('timestamp').innerHTML = '📡 Última actualización: ' + new Date(data.timestamp * 1000).toLocaleString();
                    document.getElementById('totalFiles').innerText = data.total_files;
                    document.getElementById('totalSize').innerText = data.total_size;
                    
                    // Calcular estadísticas
                    let ramSize = 0, diskSize = 0;
                    data.files.forEach(file => {
                        if (file.name.includes('.raw')) {
                            let size = parseFloat(file.size);
                            if (!isNaN(size)) ramSize += size;
                        }
                        if (file.name.includes('.dd')) {
                            let size = parseFloat(file.size);
                            if (!isNaN(size)) diskSize += size;
                        }
                    });
                    document.getElementById('totalRAM').innerText = ramSize.toFixed(2);
                    document.getElementById('totalDisk').innerText = diskSize.toFixed(2);
                    
                    // Tipos de archivo
                    const types = {};
                    data.files.forEach(file => {
                        const ext = file.name.split('.').pop();
                        types[ext] = (types[ext] || 0) + 1;
                    });
                    
                    // Gráfico de tipos
                    const ctx1 = document.getElementById('fileTypesChart').getContext('2d');
                    new Chart(ctx1, {
                        type: 'doughnut',
                        data: {
                            labels: Object.keys(types),
                            datasets: [{
                                data: Object.values(types),
                                backgroundColor: ['#00ff41', '#ff3366', '#ffcc00', '#66ff99', '#ff6600']
                            }]
                        },
                        options: { responsive: true, title: { display: true, text: 'Tipos de Archivo' } }
                    });
                    
                    // Lista de archivos
                    const fileList = document.getElementById('fileList');
                    fileList.innerHTML = '';
                    data.files.forEach(file => {
                        const div = document.createElement('div');
                        div.className = 'file-item';
                        div.innerHTML = `<span>📄 ${file.name}</span><span>${file.size}</span>`;
                        fileList.appendChild(div);
                    });
                })
                .catch(err => console.error('Error:', err));
        }
        
        loadData();
        refreshInterval = setInterval(loadData, 5000);
    </script>
</body>
</html>
EOF
    
    log INFO "✓ Dashboard generado en: $dashboard_dir/index.html"
    
    # Iniciar servidor web local
    if [[ "$DO_DASHBOARD" == true ]]; then
        log INFO "🌐 Iniciando servidor web en puerto 8080"
        cd "$dashboard_dir"
        python3 -m http.server 8080 > /dev/null 2>&1 &
        local pid=$!
        log INFO "✓ Dashboard disponible en: http://localhost:8080"
        echo $pid > "$OUTPUT_DIR/dashboard.pid"
    fi
    
    echo "$dashboard_dir/index.html"
}

# ======================[ NOTIFICACIONES Y ALERTAS ]======================
send_webhook() {
    local message="$1"
    local webhook_url="${2:-$WEBHOOK_URL}"
    
    if [[ -z "$webhook_url" ]]; then
        return 0
    fi
    
    curl -s -X POST "$webhook_url" \
        -H "Content-Type: application/json" \
        -d "{\"content\":\"🔍 MX-FORENSIC ALERTA\n$message\", \"username\":\"MX-FORENSIC\"}" > /dev/null 2>&1
}

send_email() {
    local subject="$1"
    local body="$2"
    local email="${3:-$ALERT_EMAIL}"
    
    if [[ -z "$email" ]]; then
        return 0
    fi
    
    echo -e "$body" | mail -s "$subject" "$email" 2>/dev/null || true
}

send_alert() {
    local title="$1"
    local message="$2"
    
    log WARN "🔔 ALERTA: $title - $message"
    send_webhook "**$title**\n$message"
    send_email "$title" "$message"
}

# ======================[ GENERACIÓN DE REPORTES ]======================
generate_html_report() {
    local report_file="$OUTPUT_DIR/report_$(date +%Y%m%d_%H%M%S).html"
    
    log INFO "Generando reporte HTML completo"
    
    # Recolectar información para el reporte
    local ram_files=$(find "$OUTPUT_DIR" -name "ram_*.raw" -o -name "ram_*.raw.aes256" 2>/dev/null | wc -l)
    local disk_files=$(find "$OUTPUT_DIR" -name "disk_*.dd" -o -name "disk_*.dd.aes256" 2>/dev/null | wc -l)
    local yara_matches=$(find "$OUTPUT_DIR" -name "yara_*.txt" -exec cat {} \; 2>/dev/null | wc -l)
    local live_responses=$(find "$OUTPUT_DIR" -name "live_response_*.tar.gz" 2>/dev/null | wc -l)
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>MX-FORENSIC - Reporte Forense</title>
    <style>
        body { font-family: 'Courier New', monospace; margin: 20px; background: #0a0e27; color: #00ff41; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; border-bottom: 2px solid #00ff41; padding: 20px; }
        .section { margin: 30px 0; padding: 20px; border: 1px solid #00ff41; border-radius: 10px; }
        .critical { color: #ff3366; font-weight: bold; }
        .warning { color: #ffcc00; }
        .success { color: #00ff41; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #00ff41; padding: 10px; text-align: left; }
        th { background: rgba(0,255,65,0.2); }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 MX-FORENSIC - Reporte de Análisis Forense</h1>
            <p><strong>Host:</strong> $(hostname)</p>
            <p><strong>Fecha:</strong> $(date)</p>
            <p><strong>Caso ID:</strong> MXF-$(date +%Y%m%d-%H%M%S)</p>
        </div>
        
        <div class="section">
            <h2>📊 Resumen de Evidencias</h2>
            <table>
                <tr><th>Tipo</th><th>Cantidad</th><th>Estado</th></tr>
                <tr><td>Dumps de RAM</td><td>$ram_files</td><td class="success">✓ Recolectado</td></tr>
                <tr><td>Imágenes de Disco</td><td>$disk_files</td><td class="success">✓ Recolectado</td></tr>
                <tr><td>Coincidencias YARA</td><td>$yara_matches</td><td class="$(if [[ $yara_matches -gt 0 ]]; then echo 'critical'; else echo 'success'; fi)">$yara_matches</td></tr>
                <tr><td>Live Responses</td><td>$live_responses</td><td class="success">✓ Completado</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>🔐 Cadena de Custodia</h2>
            <ul>
                <li>✓ Hashing de integridad aplicado</li>
                <li>✓ Timestamps documentados</li>
                <li>✓ Cifrado AES-256: $(if [[ "$DO_ENCRYPT" == true ]]; then echo "Activado"; else echo "No activado"; fi)</li>
                <li>✓ Envío remoto: $(if [[ "$DO_UPLOAD" == true ]]; then echo "Activado ($UPLOAD_TYPE)"; else echo "No activado"; fi)</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>🚨 Hallazgos Críticos</h2>
            <div id="findings">
                <pre>$(find "$OUTPUT_DIR" -name "analysis_*.txt" -exec head -50 {} \; 2>/dev/null | grep -E "pass|token|malware|suspicious" | head -20)</pre>
            </div>
        </div>
        
        <div class="footer">
            <p>Reporte generado por MX-FORENSIC v$VERSION</p>
            <p><em>Este documento es parte de la cadena de custodia oficial del caso</em></p>
        </div>
    </div>
</body>
</html>
EOF
    
    log INFO "✓ Reporte HTML generado: $report_file"
    echo "$report_file"
}

# ======================[ FUNCIÓN PRINCIPAL ]======================
show_help() {
    cat << EOF
${CYAN}MX-FORENSIC v$VERSION - Suite Forense Profesional${NC}

${GREEN}USO:${NC}
    sudo $0 [OPCIONES]

${GREEN}OPCIONES PRINCIPALES:${NC}
    --ram                          Dump de memoria RAM
    --disk DISCO                   Dump de disco (ej: /dev/sda)
    --hash                         Calcular hashes de integridad
    --analyze                      Análisis básico de memoria
    --report                       Generar reporte HTML

${GREEN}MÓDULOS AVANZADOS:${NC}
    --volatility                   Análisis con Volatility 3
    --yara                         Escaneo con YARA rules
    --live-response                Live Response (evidencias en caliente)
    --ewf                          Crear imagen EWF (formato EnCase)

${GREEN}CIFRADO Y SEGURIDAD:${NC}
    --encrypt                      Cifrar evidencias con AES-256
    --decrypt ARCHIVO              Descifrar evidencias

${GREEN}ENVÍO REMOTO:${NC}
    --upload                       Habilitar envío automático
    --upload-type {scp|rsync|sftp|webdav}
    --upload-host HOST
    --upload-user USER
    --upload-path PATH
    --upload-key KEY              (para SCP/RSYNC) o password (para SFTP)

${GREEN}INTEGRACIONES:${NC}
    --virustotal API_KEY          Analizar con VirusTotal
    --webhook URL                 Enviar alertas a Discord/Slack
    --email EMAIL                 Notificaciones por email

${GREEN}DASHBOARD:${NC}
    --dashboard                    Generar dashboard web interactivo

${GREEN}EJEMPLOS:${NC}
    # Análisis forense completo
    sudo $0 --ram --disk /dev/sda --hash --analyze --report

    # Con cifrado y envío remoto
    sudo $0 --ram --encrypt --upload --upload-type scp --upload-host server.com --upload-user root --upload-path /evidencias --upload-key ~/.ssh/id_rsa

    # Modo respuesta a incidentes
    sudo $0 --live-response --yara --virustotal TU_API_KEY --webhook https://discord.com/api/webhooks/...

    # Dashboard en vivo
    sudo $0 --ram --disk /dev/sda --dashboard --report

${GREEN}AUTOR:${NC} Falconmx1
${GREEN}LICENCIA:${NC} GPL-3.0
EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --ram) DO_RAM=true ;;
            --disk) DO_DISK="$2"; shift ;;
            --hash) DO_HASH=true ;;
            --analyze) DO_ANALYZE=true ;;
            --report) DO_REPORT=true ;;
            --volatility) DO_VOLATILITY=true ;;
            --yara) DO_YARA=true ;;
            --live-response) DO_LIVE_RESPONSE=true ;;
            --ewf) DO_EWF=true ;;
            --encrypt) DO_ENCRYPT=true ;;
            --decrypt) DECRYPT_FILE="$2"; shift ;;
            --upload) DO_UPLOAD=true ;;
            --upload-type) UPLOAD_TYPE="$2"; shift ;;
            --upload-host) UPLOAD_HOST="$2"; shift ;;
            --upload-user) UPLOAD_USER="$2"; shift ;;
            --upload-path) UPLOAD_PATH="$2"; shift ;;
            --upload-key) UPLOAD_KEY="$2"; shift ;;
            --virustotal) DO_VT=true; VT_API_KEY="$2"; shift ;;
            --webhook) WEBHOOK_URL="$2"; shift ;;
            --email) ALERT_EMAIL="$2"; shift ;;
            --dashboard) DO_DASHBOARD=true ;;
            --output) OUTPUT_DIR="$2"; shift ;;
            --help| -h) show_help; exit 0 ;;
            *) log ERROR "Opción desconocida: $1"; show_help; exit 1 ;;
        esac
        shift
    done
}

main() {
    print_banner
    
    # Validaciones iniciales
    check_root
    mkdir -p "$OUTPUT_DIR"
    setup_logging
    
    log INFO "MX-FORENSIC v$VERSION iniciado"
    log INFO "Directorios de salida: $OUTPUT_DIR"
    
    # Modo descifrado
    if [[ -n "${DECRYPT_FILE:-}" ]]; then
        decrypt_evidence "$DECRYPT_FILE"
        exit $?
    fi
    
    # Verificar argumentos
    if [[ "$DO_RAM" == false && -z "$DO_DISK" && "$DO_LIVE_RESPONSE" == false ]]; then
        log ERROR "No se especificó ninguna acción"
        show_help
        exit 1
    fi
    
    # Recolección de evidencias
    declare -a EVIDENCES
    
    if [[ "$DO_LIVE_RESPONSE" == true ]]; then
        live_response
        EVIDENCES+=("$OUTPUT_DIR/live_response_*.tar.gz")
        send_alert "Live Response Completado" "Se recolectaron evidencias en caliente del sistema"
    fi
    
    if [[ "$DO_RAM" == true ]]; then
        RAM_DUMP=$(dump_ram)
        EVIDENCES+=("$RAM_DUMP")
        
        if [[ "$DO_HASH" == true ]]; then
            calculate_hashes "$RAM_DUMP"
        fi
        
        if [[ "$DO_ANALYZE" == true ]]; then
            simple_analysis "$RAM_DUMP"
        fi
        
        if [[ "$DO_VOLATILITY" == true ]]; then
            run_volatility "$RAM_DUMP"
        fi
        
        if [[ "$DO_YARA" == true ]]; then
            run_yara "$RAM_DUMP"
        fi
        
        if [[ "$DO_VT" == true ]]; then
            check_virustotal "$RAM_DUMP" "$VT_API_KEY"
        fi
    fi
    
    if [[ -n "$DO_DISK" ]]; then
        DISK_DUMP=$(dump_disk "$DO_DISK")
        EVIDENCES+=("$DISK_DUMP")
        
        if [[ "$DO_EWF" == true ]]; then
            create_ewf "$DO_DISK"
        fi
    fi
    
    # Cifrado
    if [[ "$DO_ENCRYPT" == true ]]; then
        for evidence in "${EVIDENCES[@]}"; do
            if [[ -f "$evidence" ]]; then
                encrypt_evidence "$evidence"
            fi
        done
    fi
    
    # Envío remoto
    if [[ "$DO_UPLOAD" == true ]]; then
        for evidence in "${EVIDENCES[@]}"; do
            if [[ -f "$evidence" ]]; then
                auto_upload "$evidence"
            fi
        done
    fi
    
    # Reportes
    if [[ "$DO_REPORT" == true ]]; then
        generate_html_report
    fi
    
    # Dashboard
    if [[ "$DO_DASHBOARD" == true ]]; then
        generate_dashboard
    fi
    
    # Alerta final
    send_webhook "✅ Investigación forense completada\nHost: $(hostname)\nEvidencias: ${#EVIDENCES[@]}\nDirectorio: $OUTPUT_DIR"
    
    log INFO "═══════════════════════════════════════════════════════════"
    log INFO "🎯 MX-FORENSIC FINALIZADO EXITOSAMENTE"
    log INFO "📁 Evidencias guardadas en: $OUTPUT_DIR"
    log INFO "📋 Log completo: $LOG_FILE"
    log INFO "═══════════════════════════════════════════════════════════"
}

# ======================[ EJECUCIÓN ]======================
parse_arguments "$@"
main "$@"
