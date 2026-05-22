#!/usr/bin/env python3
"""
MX-FORENSIC - Volatility 3 Memory Analysis Module
Analiza dumps de RAM para extraer procesos, conexiones, DLLs, y más.
"""

import os
import sys
import json
import argparse
from pathlib import Path
import subprocess

class VolatilityAnalyzer:
    def __init__(self, memory_dump, output_dir):
        self.memory_dump = memory_dump
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def check_volatility(self):
        """Verifica que Volatility 3 esté instalado"""
        try:
            result = subprocess.run(['vol', '-h'], capture_output=True, text=True)
            return True
        except FileNotFoundError:
            print("[!] Volatility 3 no encontrado. Instalalo con: pip3 install volatility3")
            return False
    
    def run_plugin(self, plugin, output_file):
        """Ejecuta un plugin de Volatility y guarda el resultado"""
        print(f"[*] Ejecutando plugin: {plugin}")
        cmd = ['vol', '-f', self.memory_dump, plugin]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            output_path = self.output_dir / output_file
            
            with open(output_path, 'w') as f:
                f.write(result.stdout)
            
            if result.stderr:
                with open(output_path, 'a') as f:
                    f.write("\n=== ERRORS ===\n")
                    f.write(result.stderr)
            
            print(f"[+] {plugin} guardado en {output_path}")
            return True
        except subprocess.TimeoutExpired:
            print(f"[!] Timeout en plugin {plugin}")
            return False
    
    def analyze_all(self):
        """Ejecuta análisis completo"""
        if not self.check_volatility():
            return False
        
        print(f"[+] Analizando: {self.memory_dump}")
        
        # Plugins esenciales para análisis forense
        plugins = {
            'windows.pslist.PsList': 'pslist.txt',
            'windows.psscan.PsScan': 'psscan.txt',
            'windows.dlllist.DllList': 'dlllist.txt',
            'windows.netscan.NetScan': 'netscan.txt',
            'windows.cmdline.CmdLine': 'cmdline.txt',
            'windows.envars.Envars': 'envars.txt',
            'windows.filescan.FileScan': 'filescan.txt',
            'windows.malfind.Malfind': 'malfind.txt',
            'windows.modscan.ModScan': 'modscan.txt',
            'windows.svcscan.SvcScan': 'svcscan.txt',
            'windows.registry.hivelist.HiveList': 'hivelist.txt',
            'windows.registry.userassist.UserAssist': 'userassist.txt',
            'windows.registry.shimcache.ShimCache': 'shimcache.txt',
            'windows.handles.Handles': 'handles.txt',
            'windows.mftscan.MFTScan': 'mftscan.txt'
        }
        
        results = {}
        for plugin, output_file in plugins.items():
            success = self.run_plugin(plugin, output_file)
            results[plugin] = success
        
        # Generar reporte JSON resumido
        self.generate_summary(results)
        return True
    
    def generate_summary(self, results):
        """Genera un resumen JSON de los hallazgos"""
        summary_file = self.output_dir / 'volatility_summary.json'
        
        summary = {
            'memory_dump': str(self.memory_dump),
            'plugins_executed': results,
            'key_findings': self.extract_key_findings()
        }
        
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"[+] Resumen JSON guardado en {summary_file}")
    
    def extract_key_findings(self):
        """Extrae hallazgos clave como procesos sospechosos"""
        findings = {'suspicious_processes': [], 'network_connections': []}
        
        # Leer pslist para encontrar procesos sospechosos
        pslist_file = self.output_dir / 'pslist.txt'
        if pslist_file.exists():
            suspicious = ['nc', 'netcat', 'ncat', 'meterpreter', 'shell', 'reverse', 
                         'powershell -enc', 'cmd.exe /c', 'wget', 'curl', 'plink']
            
            with open(pslist_file, 'r') as f:
                for line in f:
                    for sus in suspicious:
                        if sus.lower() in line.lower():
                            findings['suspicious_processes'].append(line.strip())
        
        # Leer netscan para conexiones de red
        netscan_file = self.output_dir / 'netscan.txt'
        if netscan_file.exists():
            with open(netscan_file, 'r') as f:
                for line in f:
                    if 'ESTABLISHED' in line or 'LISTENING' in line:
                        findings['network_connections'].append(line.strip())
        
        return findings

def main():
    parser = argparse.ArgumentParser(description='MX-FORENSIC Volatility Analysis Module')
    parser.add_argument('--memory', required=True, help='Ruta al dump de memoria RAM')
    parser.add_argument('--output', default='./outputs', help='Directorio de salida')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.memory):
        print(f"[!] Archivo no encontrado: {args.memory}")
        sys.exit(1)
    
    analyzer = VolatilityAnalyzer(args.memory, args.output)
    analyzer.analyze_all()

if __name__ == '__main__':
    main()
