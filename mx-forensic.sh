#!/bin/bash
# MX-FORENSIC - Linux Memory & Disk Forensics Tool
# Uso: sudo ./mx-forensic.sh --ram --disk /dev/sda --output ./caso

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

OUTPUT_DIR="./outputs"
DO_RAM=false
DO_DISK=""
DO_HASH=false
DO_ANALYZE=false
DO_REPORT=false

print_help() {
    echo "MX-FORENSIC - Linux"
    echo "Uso: $0 [--ram] [--disk DISCO] [--hash] [--analyze] [--report] [--output DIR]"
    echo ""
    echo "  --ram           Dump de memoria RAM"
    echo "  --disk DISCO    Imagen forense del disco (ej: /dev/sda)"
    echo "  --hash          Calcular hashes MD5/SHA1/SHA256"
    echo "  --analyze       Análisis básico de la RAM dump"
    echo "  --report        Generar reporte HTML"
    echo "  --output DIR    Directorio de salida (default: ./outputs)"
    echo "  --help          Esta ayuda"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --ram) DO_RAM=true ;;
        --disk) DO_DISK="$2"; shift ;;
        --hash) DO_HASH=true ;;
        --analyze) DO_ANALYZE=true ;;
        --report) DO_REPORT=true ;;
        --output) OUTPUT_DIR="$2"; shift ;;
        --help) print_help; exit 0 ;;
        *) echo "Opción desconocida: $1"; print_help; exit 1 ;;
    esac
    shift
done

mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
HOSTNAME=$(hostname)

echo -e "${GREEN}[+] MX-FORENSIC iniciado en $HOSTNAME - $TIMESTAMP${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Ejecuta como root (sudo)${NC}"
    exit 1
fi

# RAM DUMP
if [ "$DO_RAM" = true ]; then
    RAM_FILE="$OUTPUT_DIR/ram_${HOSTNAME}_${TIMESTAMP}.raw"
    echo -e "${YELLOW}[*] Dumping RAM a $RAM_FILE ...${NC}"
    
    if command -v avml &> /dev/null; then
        avml "$RAM_FILE"
    elif [ -f /proc/kcore ]; then
        dd if=/proc/kcore of="$RAM_FILE" bs=1M status=progress 2>/dev/null
    else
        echo -e "${RED}[!] No se pudo dumpiar RAM. Instala avml o liME${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] RAM dump completado: $(du -h "$RAM_FILE" | cut -f1)${NC}"
fi

# DISK DUMP
if [ -n "$DO_DISK" ]; then
    DISK_FILE="$OUTPUT_DIR/disk_${HOSTNAME}_${TIMESTAMP}.dd"
    echo -e "${YELLOW}[*] Dumping disco $DO_DISK a $DISK_FILE ...${NC}"
    dd if="$DO_DISK" of="$DISK_FILE" bs=4M status=progress
    echo -e "${GREEN}[+] Disco dump completado: $(du -h "$DISK_FILE" | cut -f1)${NC}"
fi

# HASHES
if [ "$DO_HASH" = true ]; then
    HASH_FILE="$OUTPUT_DIR/hashes_${TIMESTAMP}.txt"
    echo -e "${YELLOW}[*] Calculando hashes...${NC}"
    echo "# Hashes MX-FORENSIC - $TIMESTAMP" > "$HASH_FILE"
    
    for file in "$OUTPUT_DIR"/*.raw "$OUTPUT_DIR"/*.dd; do
        if [ -f "$file" ]; then
            echo "=== $(basename "$file") ===" >> "$HASH_FILE"
            md5sum "$file" >> "$HASH_FILE"
            sha1sum "$file" >> "$HASH_FILE"
            sha256sum "$file" >> "$HASH_FILE"
            echo "" >> "$HASH_FILE"
        fi
    done
    echo -e "${GREEN}[+] Hashes guardados en $HASH_FILE${NC}"
fi

# ANÁLISIS BÁSICO
if [ "$DO_ANALYZE" = true ] && [ -f "$OUTPUT_DIR"/ram_*.raw ]; then
    RAM_DUMP=$(ls "$OUTPUT_DIR"/ram_*.raw | head -1)
    ANALYZE_FILE="$OUTPUT_DIR/analysis_${TIMESTAMP}.txt"
    echo -e "${YELLOW}[*] Analizando RAM dump...${NC}"
    
    echo "=== PROCESOS ===" > "$ANALYZE_FILE"
    strings "$RAM_DUMP" | grep -E "^[a-zA-Z0-9_.-]+$" | sort -u | head -50 >> "$ANALYZE_FILE"
    
    echo -e "\n=== IPs / CONEXIONES ===" >> "$ANALYZE_FILE"
    strings "$RAM_DUMP" | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u | head -30 >> "$ANALYZE_FILE"
    
    echo -e "\n=== PALABRAS CLAVE (pass, admin, token) ===" >> "$ANALYZE_FILE"
    strings "$RAM_DUMP" | grep -E -i "pass|admin|token|key|secret" | head -20 >> "$ANALYZE_FILE"
    
    echo -e "${GREEN}[+] Análisis guardado en $ANALYZE_FILE${NC}"
fi

# REPORTE HTML
if [ "$DO_REPORT" = true ]; then
    REPORT="$OUTPUT_DIR/reporte_${TIMESTAMP}.html"
    echo -e "${YELLOW}[*] Generando reporte HTML...${NC}"
    
    cat > "$REPORT" << EOF
<!DOCTYPE html>
<html>
<head><title>MX-FORENSIC Reporte</title></head>
<body>
<h1>🔍 MX-FORENSIC Reporte</h1>
<p><b>Sistema:</b> $HOSTNAME</p>
<p><b>Fecha:</b> $TIMESTAMP</p>
<h2>Archivos generados</h2>
<ul>
EOF
    for file in "$OUTPUT_DIR"/*; do
        if [ -f "$file" ]; then
            echo "<li><code>$(basename "$file")</code> - $(du -h "$file" | cut -f1)</li>" >> "$REPORT"
        fi
    done
    echo "</ul></body></html>" >> "$REPORT"
    echo -e "${GREEN}[+] Reporte HTML: $REPORT${NC}"
fi

echo -e "${GREEN}[+] MX-FORENSIC finalizado. Resultados en $OUTPUT_DIR/${NC}"
