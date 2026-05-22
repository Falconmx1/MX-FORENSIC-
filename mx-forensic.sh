#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                    MX-FORENSIC - Suite Forense Profesional                    ║
# ║         Análisis de memoria, discos, live response, YARA, Volatility          ║
# ║    TheHive | MISP | ELK Stack | ML Anomaly Detection | Cloud | Mobile        ║
# ║                              v4.0.0 FINAL                                     ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
# Autor: Falconmx1
# Licencia: GPL-3.0

set -euo pipefail

# ======================[ CONFIGURACIÓN GLOBAL ]======================
VERSION="4.0.0"
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
DO_THEHIVE=false
DO_MISP=false
DO_AUTO_CLASSIFY=false
DO_ELK=false
DO_ML=false
DO_CLOUD=false
DO_MOBILE=false

# Configuración remota
UPLOAD_TYPE=""
UPLOAD_HOST=""
UPLOAD_USER=""
UPLOAD_PATH=""
UPLOAD_KEY=""
VT_API_KEY=""
WEBHOOK_URL=""
ALERT_EMAIL=""
ENCRYPT_PASSPHRASE=""
THEHIVE_CASE_ID=""
MISP_EVENT_ID=""

# Configuración Cloud
CLOUD_PROVIDER=""
AWS_PROFILE="default"
AWS_BUCKET=""
AZURE_STORAGE=""
GCP_BUCKET=""

# Configuración Mobile
MOBILE_EXTRACTION_DIR=""
ANDROID_ROOT=false

# ======================[ FUNCIONES DE UTILIDAD ]======================
print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ███╗   ███╗██╗  ██╗     ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗██╗██████╗
║   ████╗ ████║╚██╗██╔╝     ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██║██╔══██╗
║   ██╔████╔██║ ╚███╔╝█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║██║██████╔╝
║   ██║╚██╔╝██║ ██╔██╗╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║██║██╔══██╗
║   ██║ ╚═╝ ██║██╔╝ ██╗     ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║██║██║  ██║
║   ╚═╝     ╚═╝╚═╝  ╚═╝     ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝
║                                                                               ║
║                    FORENSIC SUITE v$VERSION - FINAL                            ║
║              ELK | ML | CLOUD | MOBILE | THEHIVE | MISP                       ║
╚═══════════════════════════════════════════════════════════════════════════════╝
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
        log ERROR "Ejecutar como root"
        exit 1
    fi
}

check_dependencies() {
    local deps=("dd" "grep" "awk" "sed" "curl" "jq" "openssl" "tar" "python3" "pip3")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log WARN "Instalando dependencias: ${missing[*]}"
        if [[ -f /etc/debian_version ]]; then
            apt-get update -qq
            apt-get install -y -qq "${missing[@]}" python3-pip
        elif [[ -f /etc/redhat-release ]]; then
            yum install -y -q "${missing[@]}" python3-pip
        fi
    fi
    
    log INFO "✓ Dependencias verificadas"
}

# ======================[ NÚCLEO FORENSE ]======================
dump_ram() {
    local output_file="$OUTPUT_DIR/ram_${HOSTNAME}_$(date +%Y%m%d_%H%M%S).raw"
    log INFO "Dump RAM: $output_file"
    
    if command -v avml &> /dev/null; then
        avml "$output_file"
    elif [[ -f /proc/kcore ]]; then
        dd if=/proc/kcore of="$output_file" bs=1M status=progress 2>&1
    else
        log ERROR "No se pudo dumpiar RAM"
        return 1
    fi
    
    echo "$output_file"
}

dump_disk() {
    local disk="$1"
    local output_file="$OUTPUT_DIR/disk_${HOSTNAME}_$(date +%Y%m%d_%H%M%S).dd"
    log INFO "Dump disco: $disk -> $output_file"
    
    dd if="$disk" of="$output_file" bs=4M status=progress 2>&1
    echo "$output_file"
}

calculate_hashes() {
    local file="$1"
    local hash_file="$OUTPUT_DIR/hashes_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "=== HASHES MX-FORENSIC ==="
        echo "Archivo: $(basename "$file")"
        echo "MD5:    $(md5sum "$file" | cut -d' ' -f1)"
        echo "SHA1:   $(sha1sum "$file" | cut -d' ' -f1)"
        echo "SHA256: $(sha256sum "$file" | cut -d' ' -f1)"
    } | tee "$hash_file"
    
    echo "$hash_file"
}

simple_analysis() {
    local ram_dump="$1"
    local analysis_file="$OUTPUT_DIR/analysis_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "=== PROCESOS ==="
        strings "$ram_dump" 2>/dev/null | grep -E '^[a-zA-Z0-9_.-]+\.(exe|dll|so)$' | sort -u | head -100
        
        echo -e "\n=== CONEXIONES ==="
        strings "$ram_dump" 2>/dev/null | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+' | sort -u | head -50
        
        echo -e "\n=== PALABRAS CLAVE ==="
        strings "$ram_dump" 2>/dev/null | grep -E -i "pass|token|secret|key" | head -50
    } > "$analysis_file"
    
    echo "$analysis_file"
}

# ======================[ MÓDULOS AVANZADOS ]======================
run_volatility() {
    local ram_dump="$1"
    local vol_output="$OUTPUT_DIR/volatility_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$vol_output"
    
    log INFO "Ejecutando Volatility 3"
    
    if ! command -v vol &> /dev/null; then
        pip3 install volatility3 &> /dev/null
    fi
    
    local plugins=("windows.pslist.PsList" "windows.netscan.NetScan" "windows.malfind.Malfind")
    for plugin in "${plugins[@]}"; do
        vol -f "$ram_dump" "$plugin" > "$vol_output/${plugin//./_}.txt" 2>/dev/null
    done
    
    echo "$vol_output"
}

run_yara() {
    local target="$1"
    local yara_output="$OUTPUT_DIR/yara_$(date +%Y%m%d_%H%M%S).txt"
    
    log INFO "Escaneo YARA"
    
    cat > /tmp/basic_rules.yar << 'EOF'
rule Suspicious {
    strings:
        $s1 = /meterpreter|reverse_shell/i
        $s2 = /mimikatz|pwdump/i
        $s3 = "stratum+tcp://"
    condition:
        any of them
}
EOF
    
    yara -r /tmp/basic_rules.yar "$target" > "$yara_output" 2>/dev/null
    
    echo "$yara_output"
}

live_response() {
    local live_dir="$OUTPUT_DIR/live_response_${HOSTNAME}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$live_dir"
    
    log INFO "Live Response"
    
    ps auxf > "$live_dir/ps.txt"
    netstat -tupan > "$live_dir/netstat.txt"
    ss -tunap > "$live_dir/ss.txt"
    lsof -i -n -P > "$live_dir/lsof.txt"
    last -n 100 > "$live_dir/last.txt"
    cat /etc/passwd > "$live_dir/passwd.txt"
    lsmod > "$live_dir/lsmod.txt"
    dmesg | tail -200 > "$live_dir/dmesg.txt"
    systemctl list-units --all > "$live_dir/services.txt" 2>/dev/null
    free -h > "$live_dir/free.txt"
    
    tar -czf "$live_dir.tar.gz" -C "$live_dir" . 2>/dev/null
    rm -rf "$live_dir"
    
    echo "$live_dir.tar.gz"
}

create_ewf() {
    local source="$1"
    local ewf_output="$OUTPUT_DIR/ewf_${HOSTNAME}_$(date +%Y%m%d_%H%M%S)"
    
    log INFO "Creando EWF"
    
    if ! command -v ewfacquire &> /dev/null; then
        apt-get install -y libewf ewf-tools &> /dev/null
    fi
    
    ewfacquire -u -c fast -f encase5 -d "$source" -t "$ewf_output" -l "${ewf_output}.log" &> /dev/null
    
    echo "${ewf_output}.E01"
}

# ======================[ CIFRADO AES-256 ]======================
encrypt_evidence() {
    local file="$1"
    local passphrase="${2:-}"
    
    if [[ -z "$passphrase" ]]; then
        read -s -p "Passphrase cifrado: " passphrase
        echo
    fi
    
    local encrypted_file="${file}.aes256"
    openssl enc -aes-256-cbc -salt -pbkdf2 -in "$file" -out "$encrypted_file" -pass pass:"$passphrase"
    
    echo "$encrypted_file"
}

decrypt_evidence() {
    local encrypted_file="$1"
    local passphrase="${2:-}"
    
    if [[ -z "$passphrase" ]]; then
        read -s -p "Passphrase descifrado: " passphrase
        echo
    fi
    
    local decrypted_file="${encrypted_file%.aes256}"
    openssl enc -aes-256-cbc -d -pbkdf2 -in "$encrypted_file" -out "$decrypted_file" -pass pass:"$passphrase"
    
    echo "$decrypted_file"
}

# ======================[ ENVÍO REMOTO ]======================
upload_remote() {
    local file="$1"
    
    log INFO "Envío remoto a $UPLOAD_HOST via $UPLOAD_TYPE"
    
    case "$UPLOAD_TYPE" in
        "scp")
            scp -i "$UPLOAD_KEY" -o StrictHostKeyChecking=no "$file" "$UPLOAD_USER@$UPLOAD_HOST:$UPLOAD_PATH"
            ;;
        "rsync")
            rsync -avz -e "ssh -i $UPLOAD_KEY" "$file" "$UPLOAD_USER@$UPLOAD_HOST:$UPLOAD_PATH"
            ;;
        "sftp")
            echo "put \"$file\" \"$UPLOAD_PATH/\"" | sftp -b - "$UPLOAD_USER@$UPLOAD_HOST"
            ;;
    esac
}

# ======================[ VIRUSTOTAL ]======================
check_virustotal() {
    local file="$1"
    local api_key="$2"
    
    log INFO "Enviando a VirusTotal"
    
    local file_hash=$(sha256sum "$file" | cut -d' ' -f1)
    
    curl -s -X GET "https://www.virustotal.com/api/v3/files/${file_hash}" \
        -H "x-apikey: $api_key" > "$OUTPUT_DIR/vt_report.json" 2>/dev/null
    
    local positives=$(jq -r '.data.attributes.last_analysis_stats.malicious' "$OUTPUT_DIR/vt_report.json" 2>/dev/null)
    log INFO "VirusTotal: $positives detecciones"
}

# ======================[ THEHIVE INTEGRATION ]======================
configure_thehive() {
    local config_file="$HOME/.mx-forensic/thehive.conf"
    mkdir -p "$(dirname "$config_file")"
    
    if [[ -f "$config_file" ]]; then
        source "$config_file"
        return 0
    fi
    
    log WARN "TheHive no configurado. Crea $config_file con:"
    echo 'THEHIVE_URL="https://your-thehive.com"
THEHIVE_API_KEY="your-key"'
    return 1
}

create_thehive_case() {
    local title="MX-FORENSIC - $(hostname) - $(date +%Y%m%d)"
    local description="Caso generado automáticamente por MX-FORENSIC"
    
    local response=$(curl -s -X POST "$THEHIVE_URL/api/case" \
        -H "Authorization: Bearer $THEHIVE_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"title\":\"$title\",\"description\":\"$description\",\"severity\":2,\"tlp\":2}")
    
    echo "$response" | jq -r '.id' 2>/dev/null
}

add_thehive_artifact() {
    local case_id="$1"
    local data_type="$2"
    local data="$3"
    
    curl -s -X POST "$THEHIVE_URL/api/case/$case_id/artifact" \
        -H "Authorization: Bearer $THEHIVE_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"dataType\":\"$data_type\",\"data\":\"$data\"}" > /dev/null 2>&1
}

# ======================[ MISP INTEGRATION ]======================
configure_misp() {
    local config_file="$HOME/.mx-forensic/misp.conf"
    mkdir -p "$(dirname "$config_file")"
    
    if [[ -f "$config_file" ]]; then
        source "$config_file"
        return 0
    fi
    
    log WARN "MISP no configurado. Crea $config_file con:"
    echo 'MISP_URL="https://your-misp.com"
MISP_API_KEY="your-key"'
    return 1
}

query_misp() {
    local ioc_type="$1"
    local ioc_value="$2"
    
    local response=$(curl -s -X POST "$MISP_URL/attributes/restSearch" \
        -H "Authorization: $MISP_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"type\":\"$ioc_type\",\"value\":\"$ioc_value\"}")
    
    echo "$response" | jq '.response | length' 2>/dev/null
}

# ======================[ ELK STACK INTEGRATION ]======================
configure_elk() {
    local config_file="$HOME/.mx-forensic/elk.conf"
    mkdir -p "$(dirname "$config_file")"
    
    if [[ -f "$config_file" ]]; then
        source "$config_file"
        return 0
    fi
    
    log WARN "ELK no configurado"
    return 1
}

send_to_elasticsearch() {
    local index="mx-forensic-$(date +%Y.%m.%d)"
    local data="$1"
    
    if [[ -n "$ELASTICSEARCH_URL" ]]; then
        curl -s -X POST "$ELASTICSEARCH_URL/$index/_doc" \
            -H "Content-Type: application/json" \
            -d "$data" > /dev/null 2>&1
    fi
}

generate_elk_dashboard() {
    local elk_dir="$OUTPUT_DIR/elk_dashboard"
    mkdir -p "$elk_dir"
    
    log INFO "Generando dashboard ELK"
    
    cat > "$elk_dir/kibana_dashboard.ndjson" << 'EOF'
{"attributes":{"title":"MX-FORENSIC-Dashboard"},"id":"mx-forensic-dashboard","type":"dashboard"}
EOF
    
    cat > "$elk_dir/logstash.conf" << EOF
input {
  file {
    path => "$OUTPUT_DIR/*.json"
    start_position => "beginning"
  }
}
filter {
  json { source => "message" }
  date { match => ["timestamp", "ISO8601"] }
}
output {
  elasticsearch { hosts => ["localhost:9200"] }
  stdout { codec => rubydebug }
}
EOF
    
    log INFO "✓ Dashboard ELK: $elk_dir/"
    echo "$elk_dir"
}

# ======================[ MACHINE LEARNING ANOMALY DETECTION ]======================
run_ml_analysis() {
    local ram_dump="$1"
    local ml_output="$OUTPUT_DIR/ml_analysis_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$ml_output"
    
    log INFO "Ejecutando detección de anomalías con ML"
    
    # Crear script Python para ML
    cat > "$ml_output/ml_detector.py" << 'EOF'
#!/usr/bin/env python3
import sys, json, os, re
from collections import Counter

def extract_features(data):
    features = {
        'entropy': 0,
        'string_count': 0,
        'unique_chars': 0,
        'suspicious_patterns': []
    }
    
    strings = []
    try:
        with open(data, 'rb') as f:
            content = f.read(1024*1024)  # 1MB sample
            strings = re.findall(b'[\\x20-\\x7E]{4,}', content)
    except:
        pass
    
    features['string_count'] = len(strings)
    features['unique_chars'] = len(set(b''.join(strings[:100]))) if strings else 0
    
    # Entropía aproximada
    if strings:
        total = sum(len(s) for s in strings[:100])
        unique = len(set(b''.join(strings[:100])))
        features['entropy'] = unique / total if total > 0 else 0
    
    # Patrones sospechosos
    suspicious = ['meterpreter', 'reverse_shell', 'mimikatz', 'payload', 'beacon', 'cobalt']
    for pattern in suspicious:
        if pattern.encode() in b''.join(strings[:1000]).lower():
            features['suspicious_patterns'].append(pattern)
    
    return features

def detect_anomaly(features):
    score = 0
    if features['entropy'] > 0.7:
        score += 30
    if features['string_count'] > 10000:
        score += 20
    if features['suspicious_patterns']:
        score += 50
    
    return {
        'anomaly_score': score,
        'is_anomaly': score > 40,
        'severity': 'critical' if score > 70 else 'high' if score > 40 else 'low',
        'features': features
    }

if __name__ == '__main__':
    if len(sys.argv) > 1:
        features = extract_features(sys.argv[1])
        result = detect_anomaly(features)
        print(json.dumps(result, indent=2))
EOF
    
    python3 "$ml_output/ml_detector.py" "$ram_dump" > "$ml_output/ml_result.json"
    
    local anomaly_score=$(jq -r '.anomaly_score' "$ml_output/ml_result.json" 2>/dev/null)
    local is_anomaly=$(jq -r '.is_anomaly' "$ml_output/ml_result.json" 2>/dev/null)
    
    if [[ "$is_anomaly" == "true" ]]; then
        log WARN "⚠️ ANOMALÍA DETECTADA - Score: $anomaly_score"
        send_alert "ML Anomaly Detection" "Se detectó anomalía con score $anomaly_score en $ram_dump"
    else
        log INFO "✓ ML: Sin anomalías detectadas (score: $anomaly_score)"
    fi
    
    echo "$ml_output/ml_result.json"
}

# ======================[ CLOUD FORENSICS ]======================
configure_cloud() {
    local cloud_provider="$1"
    
    log INFO "Configurando cloud provider: $cloud_provider"
    
    case "$cloud_provider" in
        "aws")
            if ! command -v aws &> /dev/null; then
                pip3 install awscli &> /dev/null
            fi
            export AWS_PROFILE="${AWS_PROFILE:-default}"
            log INFO "✓ AWS CLI configurado"
            ;;
        "azure")
            if ! command -v az &> /dev/null; then
                curl -sL https://aka.ms/InstallAzureCLIDeb | bash &> /dev/null
            fi
            log INFO "✓ Azure CLI configurado"
            ;;
        "gcp")
            if ! command -v gcloud &> /dev/null; then
                echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
                apt-get install -y google-cloud-sdk &> /dev/null
            fi
            log INFO "✓ GCP CLI configurado"
            ;;
        *)
            log ERROR "Cloud provider no soportado: $cloud_provider"
            return 1
            ;;
    esac
}

upload_to_cloud() {
    local file="$1"
    
    log INFO "Subiendo a cloud: $CLOUD_PROVIDER"
    
    case "$CLOUD_PROVIDER" in
        "aws")
            aws s3 cp "$file" "s3://$AWS_BUCKET/mx-forensic/$(basename "$file")" --acl bucket-owner-full-control
            ;;
        "azure")
            az storage blob upload --container-name mx-forensic --file "$file" --name "$(basename "$file")" --connection-string "$AZURE_STORAGE"
            ;;
        "gcp")
            gcloud storage cp "$file" "gs://$GCP_BUCKET/mx-forensic/$(basename "$file")"
            ;;
    esac
}

# ======================[ MOBILE FORENSICS ]======================
setup_mobile_forensics() {
    log INFO "Configurando forensica móvil"
    
    # Instalar herramientas Android
    if ! command -v adb &> /dev/null; then
        apt-get install -y android-tools-adb android-tools-fastboot &> /dev/null
    fi
    
    # Instalar herramientas iOS
    if ! command -v ideviceinfo &> /dev/null; then
        apt-get install -y libimobiledevice-utils &> /dev/null
    fi
    
    log INFO "✓ Herramientas móviles listas"
}

mobile_forensics_android() {
    local output="$OUTPUT_DIR/mobile_android_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$output"
    
    log INFO "Análisis forense Android"
    
    # Verificar dispositivo
    if ! adb devices | grep -q "device$"; then
        log ERROR "No se encontró dispositivo Android conectado"
        return 1
    fi
    
    # Extraer información básica
    adb shell getprop > "$output/system_properties.txt"
    adb shell dumpsys > "$output/dumpsys.txt"
    adb shell ps -Z > "$output/processes.txt"
    adb shell netstat -an > "$output/netstat.txt"
    adb shell logcat -d > "$output/logcat.txt"
    
    # Extraer paquetes instalados
    adb shell pm list packages > "$output/packages.txt"
    adb shell pm list permissions -g > "$output/permissions.txt"
    
    # Backup de datos (si root)
    if [[ "$ANDROID_ROOT" == true ]]; then
        adb root
        adb pull /data/data/ "$output/app_data/" 2>/dev/null
    fi
    
    log INFO "✓ Forensica Android completada: $output"
    echo "$output"
}

mobile_forensics_ios() {
    local output="$OUTPUT_DIR/mobile_ios_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$output"
    
    log INFO "Análisis forense iOS"
    
    if ! ideviceinfo &> /dev/null; then
        log ERROR "No se encontró dispositivo iOS conectado"
        return 1
    fi
    
    # Extraer información
    ideviceinfo > "$output/device_info.txt"
    idevicediagnostics > "$output/diagnostics.txt"
    idevicesyslog > "$output/syslog.txt" 2>/dev/null &
    local syslog_pid=$!
    sleep 10
    kill $syslog_pid 2>/dev/null
    
    log INFO "✓ Forensica iOS completada: $output"
    echo "$output"
}

# ======================[ DASHBOARD WEB ]======================
generate_dashboard() {
    local dashboard_dir="$OUTPUT_DIR/dashboard"
    mkdir -p "$dashboard_dir"
    
    log INFO "Generando dashboard web"
    
    # JSON data
    cat > "$dashboard_dir/data.json" << EOF
{
    "timestamp": $(date +%s),
    "hostname": "$(hostname)",
    "total_files": $(find "$OUTPUT_DIR" -type f 2>/dev/null | wc -l),
    "total_size": "$(du -sh "$OUTPUT_DIR" 2>/dev/null | cut -f1)",
    "files": [
EOF
    
    find "$OUTPUT_DIR" -type f -name "*.raw" -o -name "*.dd" -o -name "*.txt" 2>/dev/null | while read file; do
        echo "{\"name\":\"$(basename "$file")\",\"size\":\"$(du -h "$file" 2>/dev/null | cut -f1)\"}," >> "$dashboard_dir/data.json"
    done
    
    sed -i '$ s/,$//' "$dashboard_dir/data.json"
    echo "]" >> "$dashboard_dir/data.json"
    
    # HTML Dashboard
    cat > "$dashboard_dir/index.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>MX-FORENSIC Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: monospace; background: #0a0e27; color: #00ff41; margin: 0; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { text-align: center; border-bottom: 2px solid #00ff41; padding: 20px; margin-bottom: 20px; }
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 20px; }
        .card { background: rgba(0,0,0,0.5); border: 1px solid #00ff41; border-radius: 10px; padding: 20px; text-align: center; }
        .value { font-size: 2em; color: #ff3366; }
        canvas { max-height: 400px; }
        .file-list { background: rgba(0,0,0,0.5); border: 1px solid #00ff41; border-radius: 10px; padding: 20px; margin-top: 20px; max-height: 400px; overflow-y: auto; }
        .file-item { padding: 5px; border-bottom: 1px solid #00ff41; display: flex; justify-content: space-between; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header"><h1>🔍 MX-FORENSIC Dashboard v4.0</h1><p id="timestamp"></p></div>
        <div class="stats"><div class="card"><div class="value" id="totalFiles">0</div><div>Archivos</div></div><div class="card"><div class="value" id="totalSize">0</div><div>Tamaño Total</div></div><div class="card"><div class="value" id="totalEvidence">0</div><div>Evidencias</div></div></div>
        <canvas id="chart"></canvas>
        <div class="file-list"><h2>📁 Evidencias</h2><div id="fileList"></div></div>
    </div>
    <script>
        function loadData() {
            fetch('data.json?'+Date.now()).then(r=>r.json()).then(d=>{
                document.getElementById('timestamp').innerHTML='📡 '+new Date(d.timestamp*1000).toLocaleString();
                document.getElementById('totalFiles').innerText=d.total_files;
                document.getElementById('totalSize').innerText=d.total_size;
                document.getElementById('totalEvidence').innerText=d.files.length;
                let ctx=document.getElementById('chart').getContext('2d');
                let types={}; d.files.forEach(f=>{let e=f.name.split('.').pop(); types[e]=(types[e]||0)+1;});
                new Chart(ctx,{type:'doughnut',data:{labels:Object.keys(types),datasets:[{data:Object.values(types),backgroundColor:['#00ff41','#ff3366','#ffcc00','#66ff99']}]}});
                document.getElementById('fileList').innerHTML=d.files.map(f=>`<div class="file-item"><span>📄 ${f.name}</span><span>${f.size}</span></div>`).join('');
            });
        }
        loadData(); setInterval(loadData,5000);
    </script>
</body>
</html>
EOF
    
    cd "$dashboard_dir"
    python3 -m http.server 8080 > /dev/null 2>&1 &
    log INFO "✓ Dashboard: http://localhost:8080"
    echo "$dashboard_dir/index.html"
}

# ======================[ REPORTES Y ALERTAS ]======================
generate_html_report() {
    local report_file="$OUTPUT_DIR/report_$(date +%Y%m%d_%H%M%S).html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head><title>MX-FORENSIC Report</title></head>
<body>
<h1>🔍 MX-FORENSIC Forensic Report</h1>
<p><b>Host:</b> $(hostname)</p>
<p><b>Date:</b> $(date)</p>
<p><b>Case ID:</b> MXF-$(date +%Y%m%d-%H%M%S)</p>
<h2>Evidence Collected</h2>
<ul>
$(find "$OUTPUT_DIR" -type f -name "*.raw" -o -name "*.dd" -o -name "*.tar.gz" | while read f; do echo "<li>$(basename "$f") - $(du -h "$f" | cut -f1)</li>"; done)
</ul>
<h2>Hash Integrity</h2>
<pre>$(find "$OUTPUT_DIR" -name "hashes_*.txt" -exec cat {} \; 2>/dev/null)</pre>
</body>
</html>
EOF
    
    echo "$report_file"
}

send_webhook() {
    local message="$1"
    [[ -z "$WEBHOOK_URL" ]] && return
    curl -s -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -d "{\"content\":\"$message\"}" > /dev/null 2>&1
}

send_email() {
    local subject="$1"
    local body="$2"
    [[ -z "$ALERT_EMAIL" ]] && return
    echo -e "$body" | mail -s "$subject" "$ALERT_EMAIL" 2>/dev/null
}

send_alert() {
    local title="$1"
    local message="$2"
    send_webhook "**$title**\n$message"
    send_email "$title" "$message"
}

correlate_with_misp() {
    local case_id="$1"
    local analysis_file="$2"
    
    log INFO "Correlacionando con MISP"
    
    # Extraer IPs del análisis
    grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$analysis_file" 2>/dev/null | sort -u | while read ip; do
        if [[ ! "$ip" =~ ^(127\.|10\.|172\.16\.|192\.168\.) ]]; then
            local misp_count=$(query_misp "ip-dst" "$ip")
            if [[ "$misp_count" -gt 0 ]]; then
                log WARN "⚠️ IP maliciosa en MISP: $ip"
                add_thehive_artifact "$case_id" "ip" "$ip"
            fi
        fi
    done
}

auto_classify_incident() {
    local analysis_file="$1"
    local case_id="$2"
    
    local score=0
    
    if grep -qi "meterpreter\|cobalt" "$analysis_file" 2>/dev/null; then
        score=$((score + 50))
    fi
    if grep -qi "stratum\|miner" "$analysis_file" 2>/dev/null; then
        score=$((score + 30))
    fi
    if grep -qi "pass\|token" "$analysis_file" 2>/dev/null; then
        score=$((score + 20))
    fi
    
    if [[ $score -ge 50 ]]; then
        send_alert "CRITICAL INCIDENT" "Severity score: $score"
        log WARN "⚠️ INCIDENTE CRÍTICO - Score: $score"
    elif [[ $score -ge 30 ]]; then
        log WARN "⚠️ Incidente de alta severidad - Score: $score"
    fi
}

# ======================[ FUNCIÓN PRINCIPAL ]======================
show_help() {
    cat << EOF
${CYAN}MX-FORENSIC v$VERSION - Suite Forense Profesional${NC}

${GREEN}USO:${NC}
    sudo $0 [OPCIONES]

${GREEN}CORE FORENSIC:${NC}
    --ram, --disk DISCO, --hash, --analyze, --report
    --volatility, --yara, --live-response, --ewf

${GREEN}SECURITY:${NC}
    --encrypt, --decrypt FILE

${GREEN}INTEGRATIONS:${NC}
    --thehive, --misp, --elk, --virustotal API_KEY
    --webhook URL, --email EMAIL, --dashboard

${GREEN}ADVANCED:${NC}
    --ml, --auto-classify

${GREEN}CLOUD:${NC}
    --cloud {aws|azure|gcp}, --aws-bucket BUCKET
    --azure-storage CONN, --gcp-bucket BUCKET

${GREEN}MOBILE:${NC}
    --mobile, --android, --ios, --android-root

${GREEN}EJEMPLOS:${NC}
    sudo $0 --ram --disk /dev/sda --hash --report
    sudo $0 --thehive --misp --auto-classify --webhook URL
    sudo $0 --ml --elk --dashboard
    sudo $0 --mobile --android
    sudo $0 --cloud aws --aws-bucket my-bucket
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
            --thehive) DO_THEHIVE=true ;;
            --misp) DO_MISP=true ;;
            --elk) DO_ELK=true ;;
            --ml) DO_ML=true ;;
            --cloud) DO_CLOUD=true; CLOUD_PROVIDER="$2"; shift ;;
            --aws-bucket) AWS_BUCKET="$2"; shift ;;
            --azure-storage) AZURE_STORAGE="$2"; shift ;;
            --gcp-bucket) GCP_BUCKET="$2"; shift ;;
            --mobile) DO_MOBILE=true ;;
            --android) MOBILE_OS="android" ;;
            --ios) MOBILE_OS="ios" ;;
            --android-root) ANDROID_ROOT=true ;;
            --auto-classify) DO_AUTO_CLASSIFY=true ;;
            --output) OUTPUT_DIR="$2"; shift ;;
            --help|-h) show_help; exit 0 ;;
            *) log ERROR "Opción desconocida: $1"; show_help; exit 1 ;;
        esac
        shift
    done
}

main() {
    print_banner
    check_root
    mkdir -p "$OUTPUT_DIR"
    setup_logging
    
    log INFO "MX-FORENSIC v$VERSION iniciado"
    log INFO "Output: $OUTPUT_DIR"
    
    # Modo descifrado
    if [[ -n "${DECRYPT_FILE:-}" ]]; then
        decrypt_evidence "$DECRYPT_FILE"
        exit $?
    fi
    
    declare -a EVIDENCES
    
    # Live Response
    if [[ "$DO_LIVE_RESPONSE" == true ]]; then
        EVIDENCES+=("$(live_response)")
    fi
    
    # RAM Dump
    if [[ "$DO_RAM" == true ]]; then
        RAM_DUMP=$(dump_ram)
        EVIDENCES+=("$RAM_DUMP")
        
        [[ "$DO_HASH" == true ]] && calculate_hashes "$RAM_DUMP"
        [[ "$DO_ANALYZE" == true ]] && ANALYSIS_FILE=$(simple_analysis "$RAM_DUMP")
        [[ "$DO_VOLATILITY" == true ]] && run_volatility "$RAM_DUMP"
        [[ "$DO_YARA" == true ]] && run_yara "$RAM_DUMP"
        [[ "$DO_VT" == true ]] && check_virustotal "$RAM_DUMP" "$VT_API_KEY"
        [[ "$DO_ML" == true ]] && run_ml_analysis "$RAM_DUMP"
    fi
    
    # Disk Dump
    if [[ -n "$DO_DISK" ]]; then
        DISK_DUMP=$(dump_disk "$DO_DISK")
        EVIDENCES+=("$DISK_DUMP")
        [[ "$DO_EWF" == true ]] && create_ewf "$DO_DISK"
    fi
    
    # Mobile Forensics
    if [[ "$DO_MOBILE" == true ]]; then
        setup_mobile_forensics
        if [[ "$MOBILE_OS" == "android" ]]; then
            mobile_forensics_android
        elif [[ "$MOBILE_OS" == "ios" ]]; then
            mobile_forensics_ios
        fi
    fi
    
    # Cifrado
    if [[ "$DO_ENCRYPT" == true ]]; then
        for evidence in "${EVIDENCES[@]}"; do
            [[ -f "$evidence" ]] && encrypt_evidence "$evidence"
        done
    fi
    
    # Envío remoto
    if [[ "$DO_UPLOAD" == true ]]; then
        for evidence in "${EVIDENCES[@]}"; do
            [[ -f "$evidence" ]] && upload_remote "$evidence"
        done
    fi
    
    # Cloud
    if [[ "$DO_CLOUD" == true ]]; then
        configure_cloud "$CLOUD_PROVIDER"
        for evidence in "${EVIDENCES[@]}"; do
            [[ -f "$evidence" ]] && upload_to_cloud "$evidence"
        done
    fi
    
    # TheHive
    if [[ "$DO_THEHIVE" == true ]] && configure_thehive; then
        CASE_ID=$(create_thehive_case)
        for evidence in "${EVIDENCES[@]}"; do
            [[ -f "$evidence" ]] && add_thehive_artifact "$CASE_ID" "file" "$(basename "$evidence")"
        done
    fi
    
    # MISP
    if [[ "$DO_MISP" == true ]] && configure_misp; then
        MISP_EVENT_ID=$(create_misp_event)
    fi
    
    # Correlación TheHive-MISP
    if [[ "$DO_THEHIVE" == true && "$DO_MISP" == true && -n "$ANALYSIS_FILE" ]]; then
        correlate_with_misp "$CASE_ID" "$ANALYSIS_FILE"
    fi
    
    # Clasificación automática
    if [[ "$DO_AUTO_CLASSIFY" == true && -n "$ANALYSIS_FILE" ]]; then
        auto_classify_incident "$ANALYSIS_FILE" "$CASE_ID"
    fi
    
    # ELK
    if [[ "$DO_ELK" == true ]]; then
        generate_elk_dashboard
    fi
    
    # Dashboard
    if [[ "$DO_DASHBOARD" == true ]]; then
        generate_dashboard
    fi
    
    # Reporte final
    if [[ "$DO_REPORT" == true ]]; then
        generate_html_report
    fi
    
    send_webhook "✅ Forense completado en $(hostname) - $(date)"
    
    log INFO "═══════════════════════════════════════════════════════════"
    log INFO "🎯 MX-FORENSIC v$VERSION FINALIZADO"
    log INFO "📁 Evidencias: $OUTPUT_DIR"
    log INFO "📋 Log: $LOG_FILE"
    log INFO "═══════════════════════════════════════════════════════════"
}

# ======================[ EJECUCIÓN ]======================
parse_arguments "$@"
main "$@"
