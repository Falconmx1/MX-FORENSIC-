#!/bin/bash
# MX-FORENSIC - Live Response Module (Linux)
# Recolecta evidencias en caliente de un sistema en ejecución

LIVE_DIR=""
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

collect_system_info() {
    local dir=$1
    
    echo -e "${GREEN}[*] Recolectando información del sistema...${NC}"
    
    # OS Information
    cat /etc/os-release > "$dir/os_release.txt"
    uname -a > "$dir/uname.txt"
    
    # Hostname
    hostname > "$dir/hostname.txt"
    
    # Fecha y tiempo
    date > "$dir/date.txt"
    uptime > "$dir/uptime.txt"
}

collect_processes() {
    local dir=$1
    
    echo -e "${GREEN}[*] Recolectando procesos...${NC}"
    
    # Lista completa de procesos
    ps auxf > "$dir/ps_auxf.txt"
    ps -eLf > "$dir/ps_threads.txt"
    
    # Procesos ocultos (comparando /proc)
    ls -la /proc/[0-9]* | grep -v "cwd" > "$dir/proc_list.txt"
    
    # Árbol de procesos
    pstree -p > "$dir/pstree.txt"
    
    # Prioridades y nice
    ps -eo pid,ni,pri,comm > "$dir/ps_priorities.txt"
}

collect_network() {
    local dir=$1
    
    echo -e "${GREEN}[*] Recolectando información de red...${NC}"
    
    # Conexiones activas
    netstat -tupan > "$dir/netstat_all.txt"
    ss -tunap > "$dir/ss_all.txt"
    
    # Escuchando sockets
    netstat -tulnp > "$dir/netstat_listening.txt"
    lsof -i -n -P > "$dir/lsof_network.txt"
    
    # Tablas de enrutamiento
    route -n > "$dir/route.txt"
    ip route show table all > "$dir/ip_route.txt"
    
    # Interfaces
    ip addr show > "$dir/ip_addr.txt"
    ifconfig -a > "$dir/ifconfig.txt"
    
    # ARP cache
    arp -a > "$dir/arp.txt"
    
    # Firewall rules
    iptables -L -n -v > "$dir/iptables.txt" 2>/dev/null
    nft list ruleset > "$dir/nftables.txt" 2>/dev/null
    
    # DNS config
    cat /etc/resolv.conf > "$dir/resolv.conf"
    
    # Estadísticas de red
    netstat -s > "$dir/netstat_stats.txt"
}

collect_users_and_logs() {
    local dir=$1
    
    echo -e "${GREEN}[*] Recolectando usuarios y logs...${NC}"
    
    # Usuarios conectados
    who -a > "$dir/who.txt"
    w > "$dir/w.txt"
    last -n 100 > "$dir/last.txt"
    lastlog > "$dir/lastlog.txt"
    
    # Usuarios del sistema
    cat /etc/passwd > "$dir/passwd.txt"
    cat /etc/shadow > "$dir/shadow.txt" 2>/dev/null
    cat /etc/group > "$dir/group.txt"
    
    # Sudoers
    cat /etc/sudoers > "$dir/sudoers.txt" 2>/dev/null
    
    # Procesos de usuarios
    ps -u root > "$dir/ps_root.txt"
    for user in $(ls /home/); do
        ps -u "$user" > "$dir/ps_${user}.txt" 2>/dev/null
    done
}

collect_file_system() {
    local dir=$1
    
    echo -e "${GREEN}[*] Recolectando información del filesystem...${NC}"
    
    # Montajes
    mount > "$dir/mount.txt"
    df -h > "$dir/df.txt"
    fdisk -l > "$dir/fdisk.txt" 2>/dev/null
    
    # Archivos abiertos
    lsof > "$dir/lsof_all.txt"
    lsof +L1 > "$dir/lsof_deleted.txt"
    
    # SUID/SGID binaries (posible backdoor)
    find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null > "$dir/suid_sgid_files.txt"
    
    # Archivos modificados recientemente (últimos 7 días)
    find / -type f -mtime -7 -ls 2>/dev/null > "$dir/recent_modified_files.txt"
    
    # Archivos ocultos en /tmp y /dev/shm
    find /tmp /dev/shm -type f -name ".*" -ls 2>/dev/null > "$dir/hidden_files_temp.txt"
}

collect_kernel_and_modules() {
    local dir=$1
    
    echo -e "${GREEN}[*] Recolectando información del kernel...${NC}"
    
    # Kernel modules
    lsmod > "$dir/lsmod.txt"
    modinfo $(lsmod | tail -n +2 | awk '{print $1}') > "$dir/modinfo_all.txt" 2>/dev/null
    
    # Kernel parameters
    sysctl -a > "$dir/sysctl.txt"
    
    # Kernel ring buffer
    dmesg > "$dir/dmesg.txt"
}

collect_services_and_cron() {
    local dir=$1
    
    echo -e "${GREEN}[*] Recolectando servicios y tareas programadas...${NC}"
    
    # Services
    systemctl list-units --all > "$dir/systemctl_all.txt" 2>/dev/null
    service --status-all > "$dir/service_all.txt" 2>/dev/null
    
    # Cron jobs
    for user in $(cut -f1 -d: /etc/passwd); do
        crontab -u "$user" -l > "$dir/cron_${user}.txt" 2>/dev/null
    done
    cat /etc/crontab > "$dir/crontab_system.txt"
    ls -la /etc/cron* > "$dir/cron_dirs.txt"
    
    # Systemd timers
    systemctl list-timers --all > "$dir/systemd_timers.txt" 2>/dev/null
}

collect_memory_info() {
    local dir=$1
    
    echo -e "${GREEN}[*] Recolectando información de memoria...${NC}"
    
    # Memoria general
    free -h > "$dir/free.txt"
    cat /proc/meminfo > "$dir/meminfo.txt"
    cat /proc/swaps > "$dir/swaps.txt"
    
    # Mapeo de memoria de procesos críticos
    for pid in $(pgrep -f "sshd|bash|nginx|apache|mysql|postgres|docker"); do
        if [ -d "/proc/$pid" ]; then
            cat "/proc/$pid/maps" > "$dir/maps_pid_${pid}.txt" 2>/dev/null
            cat "/proc/$pid/status" > "$dir/status_pid_${pid}.txt" 2>/dev/null
        fi
    done
}

generate_live_report() {
    local dir=$1
    local timestamp=$2
    
    local report="$dir/live_response_report_${timestamp}.html"
    
    cat > "$report" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>MX-FORENSIC Live Response Report</title>
    <style>
        body { font-family: monospace; margin: 20px; }
        h1 { color: #0066cc; }
        h2 { color: #009900; margin-top: 30px; }
        .file { background: #f0f0f0; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>🔍 MX-FORENSIC Live Response Report</h1>
    <p><strong>Timestamp:</strong> $timestamp</p>
    <p><strong>Hostname:</strong> $(cat "$dir/hostname.txt")</p>
    
    <h2>📊 Resumen de recolecta</h2>
    <div class="file">
        <ul>
EOF
    
    # Listar archivos recolectados
    find "$dir" -type f -name "*.txt" | sort | while read -r file; do
        rel_path="${file#$dir/}"
        size=$(du -h "$file" | cut -f1)
        echo "<li><code>$rel_path</code> ($size)</li>" >> "$report"
    done
    
    cat >> "$report" << EOF
        </ul>
    </div>
    
    <h2>🚨 Indicadores de compromiso (IOCs)</h2>
    <div class="file">
        <h3>Procesos sospechosos</h3>
        <pre>
EOF
    
    # Buscar procesos sospechosos
    grep -E "nc |netcat|ncat|meterpreter|shell|reverse|bind|backdoor|rootkit" "$dir/ps_auxf.txt" >> "$report" 2>/dev/null
    
    cat >> "$report" << EOF
        </pre>
        
        <h3>Conexiones a IPs externas sospechosas</h3>
        <pre>
EOF
    
    # Buscar conexiones externas
    grep -E "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" "$dir/netstat_all.txt" | grep -v "127.0.0.1" | head -50 >> "$report" 2>/dev/null
    
    cat >> "$report" << EOF
        </pre>
        
        <h3>SUID/SGID Binaries</h3>
        <pre>
EOF
    
    head -50 "$dir/suid_sgid_files.txt" >> "$report" 2>/dev/null
    
    cat >> "$report" << EOF
        </pre>
    </div>
    
    <p><em>Reporte generado por MX-FORENSIC Live Response Module</em></p>
</body>
</html>
EOF
    
    echo -e "${GREEN}[+] Reporte HTML generado: $report${NC}"
}

main() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] Ejecutar como root${NC}"
        exit 1
    fi
    
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local hostname=$(hostname)
    LIVE_DIR="./live_response_${hostname}_${timestamp}"
    
    mkdir -p "$LIVE_DIR"
    
    echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   MX-FORENSIC Live Response Module   ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
    
    collect_system_info "$LIVE_DIR"
    collect_processes "$LIVE_DIR"
    collect_network "$LIVE_DIR"
    collect_users_and_logs "$LIVE_DIR"
    collect_file_system "$LIVE_DIR"
    collect_kernel_and_modules "$LIVE_DIR"
    collect_services_and_cron "$LIVE_DIR"
    collect_memory_info "$LIVE_DIR"
    
    generate_live_report "$LIVE_DIR" "$timestamp"
    
    # Crear tarball comprimido
    tar -czf "${LIVE_DIR}.tar.gz" "$LIVE_DIR"
    
    echo -e "${GREEN}[+] Live Response completado${NC}"
    echo -e "${GREEN}[+] Directorio: $LIVE_DIR${NC}"
    echo -e "${GREEN}[+] Archivo comprimido: ${LIVE_DIR}.tar.gz${NC}"
}

# Si se ejecuta directamente
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
