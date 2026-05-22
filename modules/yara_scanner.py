#!/usr/bin/env python3
"""
MX-FORENSIC - YARA Malware Scanner Module
Escanea dumps de memoria y discos en busca de malware usando reglas YARA
"""

import os
import sys
import json
import yara
import argparse
from pathlib import Path
from datetime import datetime
import hashlib

class YaraScanner:
    def __init__(self, rules_dir, target_file, output_dir):
        self.rules_dir = Path(rules_dir)
        self.target_file = target_file
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.rules = None
        
    def compile_rules(self):
        """Compila todas las reglas YARA en el directorio"""
        print(f"[*] Compilando reglas YARA desde {self.rules_dir}")
        
        rule_files = {}
        for rule_file in self.rules_dir.glob("*.yar"):
            rule_files[rule_file.stem] = str(rule_file)
            print(f"    - {rule_file.name}")
        
        if not rule_files:
            print("[!] No se encontraron reglas YARA")
            return False
        
        try:
            self.rules = yara.compile(filepaths=rule_files)
            print(f"[+] Compiladas {len(rule_files)} reglas")
            return True
        except Exception as e:
            print(f"[!] Error compilando reglas: {e}")
            return False
    
    def scan_file(self):
        """Escanea el archivo objetivo con las reglas YARA"""
        if not self.rules:
            return []
        
        print(f"[*] Escaneando: {self.target_file}")
        file_size = os.path.getsize(self.target_file) / (1024**3)
        print(f"    Tamaño: {file_size:.2f} GB")
        
        try:
            matches = self.rules.match(self.target_file, timeout=60)
            return matches
        except yara.TimeoutError:
            print("[!] Timeout durante el escaneo")
            return []
        except Exception as e:
            print(f"[!] Error durante escaneo: {e}")
            return []
    
    def scan_memory_strings(self):
        """Escanea strings extraídos de memoria (útil para RAM dumps)"""
        if not self.rules:
            return []
        
        print(f"[*] Extrayendo strings de memoria...")
        
        # Extraer strings del dump
        strings_file = self.output_dir / "memory_strings.txt"
        
        # Usar strings command si está disponible
        import subprocess
        with open(strings_file, 'w') as f:
            subprocess.run(['strings', '-n', '8', self.target_file], 
                          stdout=f, stderr=subprocess.DEVNULL)
        
        print(f"[+] Strings extraídos en {strings_file}")
        
        # Escanear el archivo de strings
        matches = []
        with open(strings_file, 'r', errors='ignore') as f:
            content = f.read()
        
        for rule in self.rules:
            try:
                result = rule.match(data=content)
                matches.extend(result)
            except:
                pass
        
        return matches
    
    def generate_report(self, matches, scan_type="file"):
        """Genera reporte detallado de los hallazgos"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"yara_report_{timestamp}.json"
        html_report = self.output_dir / f"yara_report_{timestamp}.html"
        
        # Calcular hash del archivo
        file_hash = hashlib.sha256()
        with open(self.target_file, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                file_hash.update(chunk)
        
        report = {
            "timestamp": timestamp,
            "target_file": str(self.target_file),
            "target_hash_sha256": file_hash.hexdigest(),
            "scan_type": scan_type,
            "matches": []
        }
        
        for match in matches:
            match_info = {
                "rule_name": match.rule,
                "tags": list(match.tags),
                "meta": match.meta,
                "strings": []
            }
            
            for string in match.strings:
                match_info["strings"].append({
                    "identifier": string[0],
                    "data": string[2].decode('utf-8', errors='ignore')[:200]
                })
            
            report["matches"].append(match_info)
        
        # Guardar JSON
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generar HTML
        self.generate_html_report(report, html_report)
        
        print(f"[+] Reporte JSON: {report_file}")
        print(f"[+] Reporte HTML: {html_report}")
        
        return report
    
    def generate_html_report(self, report, html_file):
        """Genera reporte HTML bonito"""
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>MX-FORENSIC YARA Scan Report</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            margin: 20px;
            background: #0a0e27;
            color: #00ff41;
        }}
        h1 {{
            color: #ff3366;
            border-bottom: 2px solid #ff3366;
        }}
        .match {{
            background: #1a1f3e;
            border-left: 4px solid #ff3366;
            margin: 20px 0;
            padding: 15px;
            border-radius: 5px;
        }}
        .rule-name {{
            color: #ffcc00;
            font-size: 1.3em;
            font-weight: bold;
        }}
        .meta {{
            color: #66ff99;
            margin: 10px 0;
        }}
        .strings {{
            background: #0d1128;
            padding: 10px;
            margin: 10px 0;
            border-radius: 3px;
        }}
        .danger {{
            color: #ff4444;
        }}
        .warning {{
            color: #ffaa44;
        }}
        .info {{
            color: #44ff44;
        }}
    </style>
</head>
<body>
    <h1>🔍 MX-FORENSIC YARA Scanner Report</h1>
    
    <div class="info">
        <p><strong>Timestamp:</strong> {report['timestamp']}</p>
        <p><strong>Target:</strong> {report['target_file']}</p>
        <p><strong>SHA256:</strong> {report['target_hash_sha256'][:64]}</p>
        <p><strong>Scan Type:</strong> {report['scan_type']}</p>
        <p><strong>Matches Found:</strong> {len(report['matches'])}</p>
    </div>
"""
        
        if report['matches']:
            html_content += """
    <h2>🚨 HALLazgos de malware 🚨</h2>
"""
            for match in report['matches']:
                severity = "danger" if "malware" in str(match['tags']) else "warning"
                html_content += f"""
    <div class="match">
        <div class="rule-name">🎯 {match['rule_name']}</div>
        <div class="meta">
            <strong>Tags:</strong> {', '.join(match['tags'])}<br>
"""
                if 'description' in match['meta']:
                    html_content += f"<strong>Description:</strong> {match['meta']['description']}<br>"
                if 'author' in match['meta']:
                    html_content += f"<strong>Author:</strong> {match['meta']['author']}<br>"
                
                html_content += """
        </div>
        <div class="strings">
            <strong>📝 Strings coincidentes:</strong><br>
"""
                for s in match['strings']:
                    html_content += f"&nbsp;&nbsp;• <code>{s['identifier']}: {s['data'][:100]}</code><br>"
                
                html_content += """
        </div>
    </div>
"""
        else:
            html_content += """
    <div class="info">
        <h2>✅ No se encontraron coincidencias</h2>
        <p>El archivo escaneado no coincide con ninguna regla YARA conocida.</p>
    </div>
"""
        
        html_content += """
    <hr>
    <p><em>Reporte generado por MX-FORENSIC YARA Scanner Module</em></p>
</body>
</html>
"""
        
        with open(html_file, 'w') as f:
            f.write(html_content)

def main():
    parser = argparse.ArgumentParser(description='MX-FORENSIC YARA Malware Scanner')
    parser.add_argument('--target', required=True, help='Archivo a escanear (RAM dump, disco, etc)')
    parser.add_argument('--rules', default='./modules/yara_rules', help='Directorio de reglas YARA')
    parser.add_argument('--output', default='./outputs', help='Directorio de salida')
    parser.add_argument('--scan-strings', action='store_true', help='Escanea strings en lugar del binario (para RAM)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.target):
        print(f"[!] Target no encontrado: {args.target}")
        sys.exit(1)
    
    scanner = YaraScanner(args.rules, args.target, args.output)
    
    if not scanner.compile_rules():
        sys.exit(1)
    
    if args.scan_strings:
        matches = scanner.scan_memory_strings()
        scan_type = "strings"
    else:
        matches = scanner.scan_file()
        scan_type = "binary"
    
    if matches:
        print(f"\n[!] Encontradas {len(matches)} coincidencias!")
        for match in matches:
            print(f"    - {match.rule}")
    else:
        print("\n[+] No se encontraron coincidencias")
    
    scanner.generate_report(matches, scan_type)

if __name__ == '__main__':
    main()
