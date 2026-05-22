# 🔍 MX-FORENSIC – Análisis de memoria RAM y discos

> Herramienta forense open-source para extraer, analizar y preservar evidencias en sistemas Windows y Linux.

MX-FORENSIC está diseñada para **investigadores de seguridad, responders ante incidentes y entusiastas del DFIR** (Digital Forensics and Incident Response). Permite capturar volátil memoria RAM, realizar dumping de discos, calcular hashes de integridad y generar reportes en formatos estándar forenses.

---

## 🚀 Características principales

- ✅ **Dump de RAM** (Windows con winpmem, Linux con /dev/mem o liME)
- ✅ **Imagen forense de discos** (dd, dcfldd, o EWF)
- ✅ **Cálculo de hashes** (MD5, SHA1, SHA256) para cadenia de custodia
- ✅ **Análisis básico de memoria** (strings, búsqueda de procesos, conexiones de red)
- ✅ **Modular**: añade scripts personalizados en `/modules`
- ✅ **Multiplataforma**: funciona en **Windows** (PowerShell + WinPMEM) y **Linux** (Bash + herramientas forenses)
- ✅ **Reporte automático** en HTML / CSV / JSON

---

## 📦 Requisitos

### Windows (modo administrador)
- Windows 7 / 8 / 10 / 11 (x64)
- [WinPMEM](https://github.com/velocidex/winpmem) (incluido en `tools/`)

### Linux (root)
- Ubuntu/Debian/Kali/Parrot
- `dd`, `dcfldd`, `grep`, `strings`, `xxd`, `md5sum`, `sha256sum`
- Opcional: `avml` o `liME` para mejor dumping de RAM

---

## ⚙️ Instalación

```bash
git clone https://github.com/Falconmx1/MX-FORENSIC.git
cd MX-FORENSIC
chmod +x mx-forensic.sh   # Linux

En Windows, ejecutar PowerShell como administrador y desbloquear scripts:
Set-ExecutionPolicy Unrestricted -Scope Process

🕹️ Uso

🔹 Linux
sudo ./mx-forensic.sh --ram --disk /dev/sda --output ./caso001

🔹 Windows (PowerShell admin)
.\mx-forensic.ps1 -Ram -Disk \\.\PhysicalDrive0 -Output C:\caso001

Opciones disponibles

--ram          : Dump de memoria RAM
--disk DISCO   : Imagen forense del disco (ej: /dev/sda o \\.\PhysicalDrive0)
--hash         : Calcula hashes de integridad del dump
--analyze      : Extrae strings, procesos y conexiones de red de la RAM dump
--report       : Genera reporte HTML
--help         : Muestra esta ayuda
