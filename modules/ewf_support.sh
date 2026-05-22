#!/bin/bash
# MX-FORENSIC - EWF (E01) Support Module
# Crea imágenes forenses comprimidas formato E01 (EnCase)

EWF_TOOL="ewfacquire"
MOUNT_TOOL="ewfmount"

check_ewf_tools() {
    echo "[*] Verificando herramientas EWF..."
    
    if ! command -v $EWF_TOOL &> /dev/null; then
        echo "[!] $EWF_TOOL no encontrado. Instalando libewf..."
        
        if [[ -f /etc/debian_version ]]; then
            sudo apt-get update
            sudo apt-get install -y libewf libewf-dev ewf-tools
        elif [[ -f /etc/redhat-release ]]; then
            sudo yum install -y libewf libewf-devel
        else
            echo "[!] Instala libewf manualmente desde: https://github.com/libyal/libewf"
            return 1
        fi
    fi
    
    echo "[+] Herramientas EWF listas"
    return 0
}

create_ewf_image() {
    local source=$1
    local output_dir=$2
    local case_name=$3
    local evidence_number=$4
    
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local output_base="${output_dir}/${case_name}_${evidence_number}_${timestamp}"
    
    echo "[*] Creando imagen EWF desde: $source"
    echo "[*] Destino: ${output_base}.E01"
    
    # Parámetros forenses estándar
    $EWF_TOOL \
        -u \
        -c fast \
        -b 64 \
        -f encase5 \
        -S "MX-FORENSIC" \
        -C "$case_name" \
        -e "$evidence_number" \
        -d "$source" \
        -t "$output_base" \
        -l "${output_base}.log"
    
    if [ $? -eq 0 ]; then
        echo "[+] Imagen EWF creada exitosamente"
        
        # Crear archivo de metadatos
        cat > "${output_base}.metadata.txt" << EOF
Imagen Forense EWF - MX-FORENSIC
================================
Fuente: $source
Caso: $case_name
Evidencia #: $evidence_number
Fecha: $(date)
Herramienta: $EWF_TOOL
Tamaño original: $(ls -lh $source 2>/dev/null | awk '{print $5}')
EOF
        
        # Calcular hashes del E01
        echo "[*] Calculando hashes del E01..."
        md5sum "${output_base}.E01" >> "${output_base}.metadata.txt"
        sha256sum "${output_base}.E01" >> "${output_base}.metadata.txt"
        
        echo "[+] Metadatos guardados en: ${output_base}.metadata.txt"
    else
        echo "[!] Error creando imagen EWF"
        return 1
    fi
}

mount_ewf_image() {
    local ewf_file=$1
    local mount_point=$2
    
    mkdir -p "$mount_point"
    
    echo "[*] Montando EWF: $ewf_file en $mount_point"
    $MOUNT_TOOL "$ewf_file" "$mount_point"
    
    if [ $? -eq 0 ]; then
        echo "[+] EWF montado en $mount_point"
        
        # Mostrar particiones dentro del EWF
        echo "[*] Particiones disponibles:"
        ls -la "$mount_point"
        
        # Montar la primera partición si existe
        if [ -f "${mount_point}/ewf1" ]; then
            sudo mount -o ro,loop "${mount_point}/ewf1" "${mount_point}/mount"
            echo "[+] Partición montada en ${mount_point}/mount"
        fi
    else
        echo "[!] Error montando EWF"
    fi
}

verify_ewf_image() {
    local ewf_file=$1
    
    echo "[*] Verificando integridad de EWF: $ewf_file"
    ewfverify "$ewf_file"
    
    if [ $? -eq 0 ]; then
        echo "[+] EWF verificado correctamente"
    else
        echo "[!] La verificación del EWF falló"
    fi
}

export_ewf_to_raw() {
    local ewf_file=$1
    local output_raw=$2
    
    echo "[*] Exportando EWF a RAW: $output_raw"
    ewfexport "$ewf_file" -t "$output_raw" -f raw
    
    if [ $? -eq 0 ]; then
        echo "[+] Exportado a formato RAW: ${output_raw}.raw"
    fi
}

# Función principal
main() {
    case $1 in
        create)
            check_ewf_tools || exit 1
            create_ewf_image "$2" "$3" "$4" "$5"
            ;;
        mount)
            mount_ewf_image "$2" "$3"
            ;;
        verify)
            verify_ewf_image "$2"
            ;;
        export)
            export_ewf_to_raw "$2" "$3"
            ;;
        *)
            echo "Uso: $0 {create|mount|verify|export} [args]"
            echo ""
            echo "  create /dev/sda ./outputs Caso001 E001"
            echo "  mount ./outputs/caso.E01 /mnt/ewf"
            echo "  verify ./outputs/caso.E01"
            echo "  export ./outputs/caso.E01 ./exported"
            ;;
    esac
}

if [ "${BASH_SOURCE[0]}" != "${0}" ]; then
    export -f check_ewf_tools create_ewf_image mount_ewf_image verify_ewf_image export_ewf_to_raw
else
    main "$@"
fi
