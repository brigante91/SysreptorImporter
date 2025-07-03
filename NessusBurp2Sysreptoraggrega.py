#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Nessus2Sysreptor.py
Script unificato per importare vulnerabilità Nessus/Burp su SysReptor, generare CSV da Nessus e allegarlo come nota.
"""

import os
import sys
import argparse
import subprocess
import logging
import xml.etree.ElementTree as ET
import csv
import datetime
import tempfile
import re
import pandas as pd
from openpyxl import load_workbook
from openpyxl.worksheet.table import Table, TableStyleInfo
from collections import defaultdict
try:
    from termcolor import colored
except ImportError:
    def colored(text, color=None, attrs=None):
        return text

# Costanti design ID italiano(da VulnImport2sysreport.sh)
BURP_DESIGN_IT_ID = "b953e220-5889-4acf-be10-2346709b8201"
NESSUS_DESIGN_IT_ID = "87b1eb27-a72a-40e8-93c8-7ade13451af4"

# Costanti design ID inglese(da VulnImport2sysreport.sh)
BURP_DESIGN_ENG_ID = "b953e220-5889-4acf-be10-2346709b8201"
NESSUS_DESIGN_ENG_ID = "6ca2ecf6-7a39-413e-a92c-fd05dfe5e571v"


logger = logging.getLogger('Nessus2Sysreptor')
logging.basicConfig(level=logging.INFO, handlers=[logging.StreamHandler(sys.stdout)],
                    format='%(asctime)s - [%(levelname)s] - %(message)s')

SUCCESS = colored('✓', 'green')
ERROR = colored('✗', 'red')
STEP = colored('➜', 'cyan')
BOLD = lambda t: colored(t, attrs=['bold'])
SEPARATOR = colored('='*50, 'yellow')

def parse_args():
    parser = argparse.ArgumentParser('Nessus2Sysreptor')
    parser.add_argument('-c', '--client', required=True, help='Nome del cliente')
    parser.add_argument('-f', '--file', required=True, help='File vulnerabilità da importare (.nessus, .xml, .html) o directory se --split')
    parser.add_argument('-s', '--severity', default='critical-high-medium-low', help='Filtro severità')
    parser.add_argument('-e', '--exclude', default='', help='IDs plugin da escludere (es: 16777984,5243392)')
    parser.add_argument('-x', '--extra', default='', help='Campo extra da aggiungere al nome progetto')
    parser.add_argument('-t', '--type', default='auto', help='Tipo forzato: burp, nessus, auto (default: auto)')
    parser.add_argument('--input-format', default='auto', help='Formato input Burp: xml, html, auto (default: auto)')
    parser.add_argument('--debug', action='store_true', help='Debug mode')
    parser.add_argument('--aggregate', action='store_true', help='Aggrega le vulnerabilità duplicate per host/servizio/nome plugin (solo Nessus)')
    parser.add_argument('--aggregate-excel', action='store_true', help='Applica aggregazione anche al file Excel generato')
    parser.add_argument('--lang', choices=['it', 'eng'], default='it', help="Lingua del progetto: 'it' o 'eng' (default: it)")
    parser.add_argument('--split', '--multi', action='store_true', help='Processa più file .nessus da una directory')
    return parser.parse_args()

# Funzione di rilevamento tipo file (da VulnImport2sysreport.sh)
def detect_file_type(file_path, forced_type):
    if forced_type != 'auto':
        return forced_type
    if file_path.lower().endswith('.nessus'):
        return 'nessus'
    if file_path.lower().endswith(('.xml', '.html', '.htm')):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            head = ''.join([next(f) for _ in range(10)])
            if any(x in head.lower() for x in ['burp', 'issues', '<html', '<!doctype']):
                return 'burp'
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        head = ''.join([next(f) for _ in range(10)])
        if any(x in head.lower() for x in ['nessusxml', 'nessusclientdata']):
            return 'nessus'
    return 'burp'

def detect_burp_format(file_path, forced_format):
    if forced_format != 'auto':
        return forced_format
    if file_path.lower().endswith('.xml'):
        return 'xml'
    if file_path.lower().endswith(('.html', '.htm')):
        return 'html'
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        head = ''.join([next(f) for _ in range(5)])
        if '<?xml' in head:
            return 'xml'
        if any(x in head.lower() for x in ['<html', '<!doctype']):
            return 'html'
    return 'xml'

# Funzione per convertire CVSS v2 in v3.1 (ispirata a reptor)
def cvss2_to_3(cvss2):
    if cvss2.startswith("CVSS:3") or cvss2.startswith("CVSS:4"):
        return cvss2
    cvss2 = cvss2.replace("CVSS2#", "")
    try:
        cvss2_metrics = {k: v for k, v in (item.split(":") for item in cvss2.split("/"))}
    except Exception:
        return ""
    cvss3 = dict()
    cvss3["AV"] = cvss2_metrics.get("AV", "N")
    cvss3["AV"] = cvss3["AV"] if cvss3["AV"] in ["L", "A", "P", "N"] else "N"
    cvss3["AC"] = cvss2_metrics.get("AC", "L")
    cvss3["AC"] = cvss3["AC"] if cvss3["AC"] in ["H", "L"] else "L"
    auth_mapping = {"M": "H", "S": "L", "N": "N"}
    cvss3["PR"] = auth_mapping.get(cvss2_metrics.get("Au", "N"), "N")
    cvss3["UI"] = "N"
    cvss3["S"] = "U"
    impact_mapping = {"C": "H", "P": "L", "N": "N"}
    cvss3["C"] = impact_mapping.get(cvss2_metrics.get("C", "N"), "N")
    cvss3["I"] = impact_mapping.get(cvss2_metrics.get("I", "N"), "N")
    cvss3["A"] = impact_mapping.get(cvss2_metrics.get("A", "N"), "N")
    return f"CVSS:3.1/{'/'.join([f'{k}:{v}' for k, v in cvss3.items()])}"

# Funzione per normalizzare il vettore CVSS
def normalize_cvss_vector(cvss3_vector, cvss_vector):
    # Priorità: cvss3_vector > cvss_vector
    vector = cvss3_vector or cvss_vector or ""
    original = vector
    if vector.startswith("CVSS:3.0/"):
        vector = vector.replace("CVSS:3.0/", "CVSS:3.1/")
    elif vector.startswith("CVSS:3.1/") or vector.startswith("CVSS:4"):
        pass  # già ok
    elif vector and (vector.startswith("CVSS:2") or "/" in vector):
        vector = cvss2_to_3(vector)
    return original, vector

def normalize_vuln_name(name):
    """
    Normalizzazione intelligente dei nomi delle vulnerabilità per l'aggregazione.
    Identifica prodotti e servizi comuni anche in nomi complessi.
    """
    name = name.strip()
    if not name:
        return name
    
    # Converti in minuscolo per il confronto
    name_lower = name.lower()
    
    # Mappatura di prodotti/servizi comuni con pattern di ricerca più flessibili
    product_patterns = [
        # Web servers
        (['apache', 'httpd'], 'Apache Multiple Vulnerabilities'),
        (['nginx'], 'Nginx Multiple Vulnerabilities'),
        (['iis', 'internet information services'], 'IIS Multiple Vulnerabilities'),
        (['lighttpd'], 'Lighttpd Multiple Vulnerabilities'),
        
        # Database
        (['mysql'], 'MySQL Multiple Vulnerabilities'),
        (['postgresql', 'postgres'], 'PostgreSQL Multiple Vulnerabilities'),
        (['mongodb'], 'MongoDB Multiple Vulnerabilities'),
        (['redis'], 'Redis Multiple Vulnerabilities'),
        (['oracle database', 'oracle db'], 'Oracle Database Multiple Vulnerabilities'),
        (['sql server', 'mssql'], 'SQL Server Multiple Vulnerabilities'),
        
        # Programming languages and frameworks
        (['php'], 'PHP Multiple Vulnerabilities'),
        (['python'], 'Python Multiple Vulnerabilities'),
        (['java', 'oracle java'], 'Java Multiple Vulnerabilities'),
        (['ruby'], 'Ruby Multiple Vulnerabilities'),
        (['perl'], 'Perl Multiple Vulnerabilities'),
        (['node.js', 'nodejs'], 'Node.js Multiple Vulnerabilities'),
        (['dotnet', '.net', 'asp.net'], 'ASP.NET Multiple Vulnerabilities'),
        
        # Web applications
        (['wordpress'], 'WordPress Multiple Vulnerabilities'),
        (['drupal'], 'Drupal Multiple Vulnerabilities'),
        (['joomla'], 'Joomla Multiple Vulnerabilities'),
        (['magento'], 'Magento Multiple Vulnerabilities'),
        (['typo3'], 'TYPO3 Multiple Vulnerabilities'),
        
        # Application servers
        (['tomcat'], 'Tomcat Multiple Vulnerabilities'),
        (['jboss', 'wildfly'], 'JBoss Multiple Vulnerabilities'),
        (['weblogic'], 'WebLogic Multiple Vulnerabilities'),
        (['websphere'], 'WebSphere Multiple Vulnerabilities'),
        
        # Security libraries
        (['openssl'], 'OpenSSL Multiple Vulnerabilities'),
        (['gnutls'], 'GnuTLS Multiple Vulnerabilities'),
        (['libssl'], 'LibSSL Multiple Vulnerabilities'),
        
        # Operating systems
        (['microsoft windows', 'windows'], 'Microsoft Windows Multiple Vulnerabilities'),
        (['linux kernel', 'kernel'], 'Linux Kernel Multiple Vulnerabilities'),
        (['ubuntu'], 'Ubuntu Multiple Vulnerabilities'),
        (['debian'], 'Debian Multiple Vulnerabilities'),
        (['centos', 'red hat', 'rhel'], 'Red Hat Multiple Vulnerabilities'),
        (['suse', 'sles'], 'SUSE Multiple Vulnerabilities'),
        
        # Office applications
        (['microsoft office', 'office'], 'Microsoft Office Multiple Vulnerabilities'),
        (['adobe acrobat', 'acrobat'], 'Adobe Acrobat Multiple Vulnerabilities'),
        (['adobe flash', 'flash'], 'Adobe Flash Multiple Vulnerabilities'),
        (['adobe reader', 'reader'], 'Adobe Reader Multiple Vulnerabilities'),
        
        # Network services
        (['ftp', 'vsftpd', 'proftpd', 'pure-ftpd'], 'FTP Multiple Vulnerabilities'),
        (['ssh', 'openssh'], 'SSH Multiple Vulnerabilities'),
        (['telnet'], 'Telnet Multiple Vulnerabilities'),
        (['smtp', 'postfix', 'sendmail', 'exim'], 'SMTP Multiple Vulnerabilities'),
        (['pop3', 'dovecot'], 'POP3 Multiple Vulnerabilities'),
        (['imap'], 'IMAP Multiple Vulnerabilities'),
        (['dns', 'bind'], 'DNS Multiple Vulnerabilities'),
        (['dhcp'], 'DHCP Multiple Vulnerabilities'),
        (['ntp'], 'NTP Multiple Vulnerabilities'),
        (['snmp'], 'SNMP Multiple Vulnerabilities'),
        (['ldap', 'openldap'], 'LDAP Multiple Vulnerabilities'),
        (['kerberos'], 'Kerberos Multiple Vulnerabilities'),
        (['samba'], 'Samba Multiple Vulnerabilities'),
        (['nfs'], 'NFS Multiple Vulnerabilities'),
        (['cifs', 'smb'], 'SMB Multiple Vulnerabilities'),
        
        # Virtualization and containers
        (['docker'], 'Docker Multiple Vulnerabilities'),
        (['kubernetes', 'k8s'], 'Kubernetes Multiple Vulnerabilities'),
        (['vmware'], 'VMware Multiple Vulnerabilities'),
        (['virtualbox'], 'VirtualBox Multiple Vulnerabilities'),
        (['xen'], 'Xen Multiple Vulnerabilities'),
        
        # Monitoring and logging
        (['elasticsearch'], 'Elasticsearch Multiple Vulnerabilities'),
        (['kibana'], 'Kibana Multiple Vulnerabilities'),
        (['logstash'], 'Logstash Multiple Vulnerabilities'),
        (['jenkins'], 'Jenkins Multiple Vulnerabilities'),
        (['nagios'], 'Nagios Multiple Vulnerabilities'),
        (['zabbix'], 'Zabbix Multiple Vulnerabilities'),
        
        # Network equipment
        (['cisco'], 'Cisco Multiple Vulnerabilities'),
        (['juniper'], 'Juniper Multiple Vulnerabilities'),
        (['fortinet', 'fortigate'], 'Fortinet Multiple Vulnerabilities'),
        (['palo alto', 'paloalto'], 'Palo Alto Multiple Vulnerabilities'),
        
        # Cloud services
        (['aws', 'amazon'], 'AWS Multiple Vulnerabilities'),
        (['azure'], 'Azure Multiple Vulnerabilities'),
        (['gcp', 'google cloud'], 'Google Cloud Multiple Vulnerabilities'),
    ]
    
    # Cerca pattern di prodotti nel nome della vulnerabilità
    for patterns, normalized in product_patterns:
        for pattern in patterns:
            if pattern in name_lower:
                return normalized
    
    # Se non trova un prodotto specifico, applica normalizzazione generica
    # Rimuove versioni, intervalli, date, parentesi, ecc.
    normalized = re.sub(r'([0-9]+\.[0-9]+(\.[0-9]+)*)', '', name)  # numeri versione
    normalized = re.sub(r'(<|>|<=|>=|=)', '', normalized)           # simboli intervallo
    normalized = re.sub(r'\(.*?\)', '', normalized)                 # parentesi
    normalized = re.sub(r'20[0-9]{2}-[0-9]{2}-[0-9]{2}', '', normalized)  # date
    normalized = re.sub(r'\s+', ' ', normalized).strip()            # spazi multipli
    
    # Se contiene già "Multiple Vulnerabilities", mantienilo così
    if 'Multiple Vulnerabilities' in normalized:
        return normalized
    # Se contiene "Vulnerabilit" (italiano) o "Vulnerability" (inglese), mantienilo
    elif 'vulnerabilit' in normalized.lower():
        return normalized
    # Altrimenti aggiungi "Multiple Vulnerabilities" se non è già presente
    else:
        return f"{normalized} Multiple Vulnerabilities" if normalized else name

def parse_nessus_file(nessus_file):
    """
    Parsing efficiente del file Nessus: estrae solo i dati necessari in una sola passata.
    Restituisce una lista di dizionari vulnerabilità.
    """
    tree = ET.parse(nessus_file)
    root = tree.getroot()
    vulns = []
    for report in root.findall('Report'):
        for host in report.findall('ReportHost'):
            host_name = host.attrib.get('name', '').strip().lower()
            mac_address = ''
            os_ = ''
            netbios_name = ''
            for tag in host.findall('.//tag'):
                if tag.attrib.get('name') == 'mac-address':
                    mac_address = tag.text or ''
                elif tag.attrib.get('name') == 'operating-system':
                    os_ = tag.text or ''
                elif tag.attrib.get('name') == 'netbios-name':
                    netbios_name = tag.text or ''
            for item in host.findall('ReportItem'):
                plugin_id = item.attrib.get('pluginID', '')
                if plugin_id == '0':
                    continue
                plugin_name = item.attrib.get('pluginName', '').replace('Detection', '').strip()
                if 'Screenshot' in plugin_name or plugin_name in ['SSL Certificate Cannot Be Trusted']:
                    continue
                cvss3_vector = item.findtext('cvss3_vector')
                cvss_vector = item.findtext('cvss_vector')
                _, normalized_vector = normalize_cvss_vector(cvss3_vector, cvss_vector)
                cvss3_base_score = item.find('cvss3_base_score')
                cvss_base_score = item.find('cvss_base_score')
                score = 0.0
                if cvss3_base_score is not None and cvss3_base_score.text:
                    try:
                        score = float(cvss3_base_score.text)
                    except Exception:
                        score = 0.0
                elif cvss_base_score is not None and cvss_base_score.text:
                    try:
                        score = float(cvss_base_score.text)
                    except Exception:
                        score = 0.0
                cve_tags = item.findall('.//cve')
                cves = [tag.text for tag in cve_tags if tag.text]
                see_also_tags = item.findall('.//see_also')
                see_alsos = [tag.text for tag in see_also_tags if tag.text]
                norm_name = normalize_vuln_name(plugin_name)
                solution = item.findtext('solution', '')
                if solution:
                    solution = solution.strip().replace('Nessus', 'System').replace('Tenable', 'System')
                vulns.append({
                    'Name': plugin_name,
                    'NormName': norm_name,
                    'Host': host_name,
                    'Port': item.attrib.get('port', ''),
                    'Protocol': item.attrib.get('protocol', ''),
                    'Service': item.attrib.get('svc_name', ''),
                    'NetBios': netbios_name,
                    'MAC Address': mac_address,
                    'Operating System': os_,
                    'Severity': get_severity_from_cvss(score),
                    'CVSS Score': score,
                    'CVSS Vector': normalized_vector,
                    'CVEs': ','.join(cves),
                    'Solution': solution,
                    'pluginID': plugin_id,
                    'pluginName': plugin_name,
                    'pluginFamily': item.attrib.get('pluginFamily', ''),
                    'description': item.findtext('description', ''),
                    'synopsis': item.findtext('synopsis', ''),
                    'risk_factor': item.findtext('risk_factor', ''),
                    'solution': solution,
                    'plugin_output': item.findtext('plugin_output', ''),
                    'see_also': see_alsos,
                })
    return vulns

# Funzioni helper per l'aggregazione
def concat_multiline_unique(values, separator='\n\n---\n\n'):
    """
    Concatena valori multilinea unici, rimuovendo duplicati e spazi inutili.
    Mantiene l'ordine alfabetico per una lettura coerente.
    """
    if not values:
        return ''
    
    # Filtra valori vuoti e normalizza spazi
    cleaned_values = []
    for val in values:
        if val and str(val).strip():
            cleaned = str(val).strip()
            if cleaned not in cleaned_values:
                cleaned_values.append(cleaned)
    
    # Ordina alfabeticamente per consistenza
    cleaned_values.sort()
    
    return separator.join(cleaned_values) if cleaned_values else ''

def join_unique_values(values, separator=', '):
    """
    Unisce valori unici in una stringa separata, rimuovendo duplicati.
    Mantiene l'ordine alfabetico.
    """
    if not values:
        return ''
    
    # Filtra valori vuoti e normalizza
    cleaned_values = []
    for val in values:
        if val and str(val).strip():
            cleaned = str(val).strip()
            if cleaned not in cleaned_values:
                cleaned_values.append(cleaned)
    
    # Ordina alfabeticamente
    cleaned_values.sort()
    
    return separator.join(cleaned_values) if cleaned_values else ''

def extract_unique_cves(cve_strings):
    """
    Estrae CVE unici da una lista di stringhe CVE separate da virgole.
    """
    cves = set()
    for cve_str in cve_strings:
        if cve_str and str(cve_str).strip():
            for cve in str(cve_str).split(','):
                cve_clean = cve.strip()
                if cve_clean and cve_clean.upper().startswith('CVE-'):
                    cves.add(cve_clean.upper())
    return sorted(list(cves))

def extract_unique_references(reference_lists):
    """
    Estrae riferimenti unici da una lista di liste di riferimenti.
    """
    refs = set()
    for ref_list in reference_lists:
        if isinstance(ref_list, list):
            for ref in ref_list:
                if ref and str(ref).strip():
                    refs.add(str(ref).strip())
        elif ref_list and str(ref_list).strip():
            refs.add(str(ref_list).strip())
    return sorted(list(refs))

def get_max_severity(severities):
    """
    Restituisce la severità più alta da una lista di severità.
    """
    severity_order = ['Info', 'Low', 'Medium', 'High', 'Critical']
    max_sev = 'Info'
    max_index = 0
    
    for sev in severities:
        sev_clean = str(sev).capitalize()
        if sev_clean in severity_order:
            sev_index = severity_order.index(sev_clean)
            if sev_index > max_index:
                max_index = sev_index
                max_sev = sev_clean
    
    return max_sev

def generate_aggregated_plugin_id(host, port, protocol, norm_name):
    """
    Genera un pluginID unico e coerente per il gruppo aggregato.
    Usa una combinazione di hash per evitare collisioni.
    """
    # Crea una stringa unica per il gruppo
    group_key = f"{host}_{port}_{protocol}_{norm_name}"
    
    # Usa hash SHA-256 per maggiore unicità e poi prendi i primi 8 caratteri
    import hashlib
    hash_obj = hashlib.sha256(group_key.encode('utf-8'))
    hash_hex = hash_obj.hexdigest()[:8]
    
    # Prefisso per identificare vulnerabilità aggregate
    return f"AGG_{hash_hex}"

def aggregate_vulnerabilities(vulns):
    """
    Funzione unificata di aggregazione che raggruppa vulnerabilità per:
    (Host, Port, Protocol, NormName)
    
    Restituisce una lista di vulnerabilità aggregate con tutti i campi
    correttamente concatenati e normalizzati.
    """
    if not vulns:
        return []
    
    # Raggruppa per la chiave di aggregazione
    groups = defaultdict(list)
    for vuln in vulns:
        key = (
            vuln['Host'],
            vuln['Port'],
            vuln['Protocol'],
            vuln['NormName']
        )
        groups[key].append(vuln)
    
    aggregated_vulns = []
    
    for (host, port, protocol, norm_name), group in groups.items():
        if len(group) == 1:
            # Se c'è solo una vulnerabilità nel gruppo, non serve aggregare
            vuln = group[0].copy()
            # Aggiungi flag per indicare che è stata processata
            vuln['_aggregated'] = False
            aggregated_vulns.append(vuln)
            continue
        
        # Aggregazione di multiple vulnerabilità
        logger.debug(f"Aggregando {len(group)} vulnerabilità per {host}:{port}/{protocol} - {norm_name}")
        
        # Estrai tutti i valori per ogni campo
        all_names = [v['Name'] for v in group if v.get('Name')]
        all_services = [v['Service'] for v in group if v.get('Service')]
        all_netbios = [v['NetBios'] for v in group if v.get('NetBios')]
        all_mac_addresses = [v['MAC Address'] for v in group if v.get('MAC Address')]
        all_os = [v['Operating System'] for v in group if v.get('Operating System')]
        all_cvss_vectors = [v['CVSS Vector'] for v in group if v.get('CVSS Vector')]
        all_cve_strings = [v['CVEs'] for v in group if v.get('CVEs')]
        all_solutions = [v['Solution'] for v in group if v.get('Solution')]
        all_plugin_ids = [v['pluginID'] for v in group if v.get('pluginID')]
        all_plugin_names = [v['pluginName'] for v in group if v.get('pluginName')]
        all_plugin_families = [v['pluginFamily'] for v in group if v.get('pluginFamily')]
        all_descriptions = [v['description'] for v in group if v.get('description')]
        all_synopsis = [v['synopsis'] for v in group if v.get('synopsis')]
        all_risk_factors = [v['risk_factor'] for v in group if v.get('risk_factor')]
        all_plugin_outputs = [v['plugin_output'] for v in group if v.get('plugin_output')]
        all_see_also = [v['see_also'] for v in group if v.get('see_also')]
        all_severities = [v['Severity'] for v in group if v.get('Severity')]
        all_cvss_scores = [v['CVSS Score'] for v in group if v.get('CVSS Score')]
        
        # Crea la vulnerabilità aggregata
        aggregated_vuln = {
            'Name': norm_name,  # Usa il nome normalizzato
            'NormName': norm_name,
            'Host': host,
            'Port': port,
            'Protocol': protocol,
            'Service': join_unique_values(all_services),
            'NetBios': join_unique_values(all_netbios),
            'MAC Address': join_unique_values(all_mac_addresses),
            'Operating System': join_unique_values(all_os),
            'Severity': get_max_severity(all_severities),
            'CVSS Score': max(all_cvss_scores) if all_cvss_scores else 0.0,
            'CVSS Vector': join_unique_values(all_cvss_vectors),
            'CVEs': join_unique_values(extract_unique_cves(all_cve_strings)),
            'Solution': concat_multiline_unique(all_solutions),
            'pluginID': generate_aggregated_plugin_id(host, port, protocol, norm_name),
            'pluginName': f"{norm_name} (Aggregated)",
            'pluginFamily': join_unique_values(all_plugin_families) or 'General',
            'description': concat_multiline_unique(all_descriptions),
            'synopsis': concat_multiline_unique(all_synopsis),
            'risk_factor': join_unique_values(all_risk_factors, separator='; '),
            'solution': concat_multiline_unique(all_solutions),
            'plugin_output': concat_multiline_unique(all_plugin_outputs),
            'see_also': extract_unique_references(all_see_also),
            '_aggregated': True,
            '_original_count': len(group),
            '_original_plugin_ids': join_unique_values(all_plugin_ids),
            '_original_names': concat_multiline_unique(all_names, separator='\n'),
        }
        
        aggregated_vulns.append(aggregated_vuln)
    
    logger.info(f"Aggregazione completata: {len(vulns)} vulnerabilità originali -> {len(aggregated_vulns)} vulnerabilità aggregate")
    return aggregated_vulns

def nessus_to_excel(nessus_file, output_excel, aggregate_excel=False):
    vulns = parse_nessus_file(nessus_file)
    if aggregate_excel:
        # Usa la nuova funzione di aggregazione unificata
        aggregated_vulns = aggregate_vulnerabilities(vulns)
        grouped = pd.DataFrame(aggregated_vulns)
        
        # Rimuovi i campi di debug per l'Excel
        if '_aggregated' in grouped.columns:
            grouped = grouped.drop(columns=['_aggregated', '_original_count', '_original_plugin_ids', '_original_names'])
    else:
        # Raggruppamento standard per Excel (senza aggregazione)
        df = pd.DataFrame(vulns)
        grouped = df.groupby(['Host', 'Port', 'Protocol', 'NormName'], as_index=False).agg({
            'Name': 'first',
            'NetBios': 'first',
            'MAC Address': 'first',
            'Operating System': 'first',
            'Service': 'first',
            'Severity': 'max',
            'CVSS Score': 'max',
            'CVSS Vector': 'first',
            'CVEs': lambda x: ', '.join(sorted(set([cve for item in x for cve in str(item).split(',') if cve.strip()]))),
            'Solution': 'first'
        })
    
    grouped.to_excel(output_excel, index=False)
    wb = load_workbook(output_excel)
    ws = wb.active
    tab = Table(displayName="VulnTable", ref=ws.dimensions)
    style = TableStyleInfo(name="TableStyleMedium9", showFirstColumn=False,
                           showLastColumn=False, showRowStripes=True, showColumnStripes=False)
    tab.tableStyleInfo = style
    ws.add_table(tab)
    wb.save(output_excel)
    return len(grouped)

def get_severity_from_cvss(cvss):
    if cvss >= 9:
        return 'Critical'
    if cvss >= 7:
        return 'High'
    if cvss >= 4:
        return 'Medium'
    if cvss > 0:
        return 'Low'
    return 'Info'

def check_reptor_installed():
    from shutil import which
    if which('reptor') is None:
        logger.error('Errore: reptor non è installato o non è nel PATH.')
        sys.exit(1)

def create_project(project_name, design_id, project_type, client_name):
    cmd = [
        'reptor', '-k', 'createproject',
        '-n', project_name,
        '-d', design_id,
        '-t', f'{project_type},{client_name}'
    ]
    logger.debug(f"Eseguo: {' '.join(cmd)}")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    logger.debug(result.stdout)
    if result.returncode != 0:
        logger.error(f"Errore creazione progetto: {result.stderr}")
        sys.exit(1)
    # Cerca l'ID sia in stdout che in stderr
    output = result.stdout + "\n" + result.stderr
    project_id = None
    for line in output.splitlines():
        logger.debug(f"Analizzo riga per ID progetto: {line!r}")
        line = line.strip()
        m = re.search(r'ID "([0-9a-fA-F-]{36})"', line)
        if m:
            logger.debug(f"Match trovato: {m.group(1)}")
            project_id = m.group(1)
            break
    if not project_id:
        logger.error("Impossibile estrarre l'ID del progetto. Output comando:")
        logger.error(output)
        print("\n[DEBUG OUTPUT]\n" + output, file=sys.stderr)
        sys.exit(1)
    return project_id

def push_findings(file_type, project_id, vuln_file, severity_filter, exclude_ids, burp_input_format, aggregate=False):
    import tempfile
    file_to_import = vuln_file
    temp_file = None
    
    if file_type == 'nessus' and aggregate:
        logger.info("Avvio aggregazione vulnerabilità Nessus...")
        vulns = parse_nessus_file(vuln_file)
        aggregated_vulns = aggregate_vulnerabilities(vulns)
        
        # Ricostruisci XML Nessus temporaneo con le vulnerabilità aggregate
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.nessus')
        temp_file_path = temp_file.name
        temp_file.close()
        
        # Ricostruzione XML ottimizzata
        tree = ET.parse(vuln_file)
        root = tree.getroot()
        new_root = ET.Element(root.tag, root.attrib)
        
        for report in root.findall('Report'):
            new_report = ET.SubElement(new_root, 'Report', report.attrib)
            
            # Raggruppa le vulnerabilità aggregate per host
            host_groups = defaultdict(list)
            for vuln in aggregated_vulns:
                host_groups[vuln['Host']].append(vuln)
            
            for host_name, host_vulns in host_groups.items():
                new_host = ET.SubElement(new_report, 'ReportHost', {'name': host_name})
                
                # Copia le proprietà dell'host originale se disponibili
                orig_host = None
                for h in report.findall('ReportHost'):
                    if h.attrib.get('name') == host_name:
                        orig_host = h
                        break
                
                if orig_host is not None:
                    host_props = orig_host.find('HostProperties')
                    if host_props is not None:
                        new_host.append(host_props)
                
                # Crea gli elementi ReportItem per ogni vulnerabilità aggregata
                for vuln in host_vulns:
                    # Usa il pluginID generato dalla funzione di aggregazione
                    plugin_id = vuln['pluginID']
                    plugin_name = vuln['pluginName']
                    
                    item = ET.SubElement(new_host, 'ReportItem', {
                        'port': str(vuln['Port']) if vuln['Port'] else '0',
                        'svc_name': str(vuln['Service']) if vuln['Service'] else 'general',
                        'protocol': str(vuln['Protocol']) if vuln['Protocol'] else 'tcp',
                        'severity': str(severity_to_int(vuln['Severity'])),
                        'pluginID': str(plugin_id),
                        'pluginName': str(plugin_name),
                        'pluginFamily': str(vuln['pluginFamily']) if vuln['pluginFamily'] else 'General',
                    })
                    
                    # Aggiungi tutti i tag obbligatori
                    tags_to_add = [
                        ('description', vuln.get('description', '')),
                        ('synopsis', vuln.get('synopsis', '')),
                        ('risk_factor', vuln.get('risk_factor', '')),
                        ('solution', vuln.get('solution', '')),
                        ('cvss_vector', vuln.get('CVSS Vector', '')),
                        ('cvss3_vector', vuln.get('CVSS Vector', '')),
                        ('cvss_base_score', str(vuln.get('CVSS Score', 0.0))),
                        ('cvss3_base_score', str(vuln.get('CVSS Score', 0.0))),
                        ('plugin_output', vuln.get('plugin_output', '')),
                    ]
                    
                    for tag_name, value in tags_to_add:
                        if value and str(value).strip():
                            sub = ET.SubElement(item, tag_name)
                            sub.text = str(value).strip()
                    
                    # Aggiungi CVE se presenti
                    if vuln.get('CVEs') and str(vuln['CVEs']).strip():
                        for cve in str(vuln['CVEs']).split(','):
                            cve_clean = cve.strip()
                            if cve_clean and cve_clean.upper().startswith('CVE-'):
                                sub = ET.SubElement(item, 'cve')
                                sub.text = cve_clean.upper()
                    
                    # Aggiungi riferimenti see_also se presenti
                    if vuln.get('see_also') and isinstance(vuln['see_also'], list):
                        for ref in vuln['see_also']:
                            if ref and str(ref).strip():
                                sub = ET.SubElement(item, 'see_also')
                                sub.text = str(ref).strip()
                    
                    # Aggiungi informazioni di debug per vulnerabilità aggregate
                    if vuln.get('_aggregated') and vuln.get('_original_count', 0) > 1:
                        debug_info = f"Vulnerabilità aggregata da {vuln['_original_count']} vulnerabilità originali.\n"
                        debug_info += f"Plugin IDs originali: {vuln.get('_original_plugin_ids', 'N/A')}\n"
                        debug_info += f"Nomi originali:\n{vuln.get('_original_names', 'N/A')}"
                        
                        debug_elem = ET.SubElement(item, 'plugin_output')
                        if vuln.get('plugin_output'):
                            debug_elem.text = f"{vuln['plugin_output']}\n\n--- DEBUG INFO ---\n{debug_info}"
                        else:
                            debug_elem.text = debug_info
        
        tree = ET.ElementTree(new_root)
        tree.write(temp_file_path, encoding='utf-8', xml_declaration=True)
        file_to_import = temp_file_path
        
        logger.info(f"XML temporaneo creato con {len(aggregated_vulns)} vulnerabilità aggregate: {temp_file_path}")
    # Importazione con reptor
    if file_type == 'burp':
        cmd = [
            'reptor', '-k', '-p', project_id, 'burp', '--push-findings'
        ]
        if severity_filter and severity_filter != 'info-critical':
            cmd += ['--severity-filter', severity_filter]
        if exclude_ids:
            cmd += ['--exclude-plugins', exclude_ids]
        if burp_input_format != 'auto':
            cmd += ['--input-format', burp_input_format]
        logger.debug(f"Eseguo: cat {file_to_import} | {' '.join(cmd)}")
        with open(file_to_import, 'rb') as f:
            result = subprocess.run(cmd, stdin=f, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    else:
        cmd = [
            'reptor', '-k', '-p', project_id, 'nessus', '-i', file_to_import, '--push-findings'
        ]
        if exclude_ids:
            cmd += ['--exclude-plugins', exclude_ids]
        logger.debug(f"Eseguo: {' '.join(cmd)}")
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    logger.debug(result.stdout)
    if result.returncode != 0:
        logger.error(f"Errore importazione vulnerabilità: {result.stderr}")
        sys.exit(1)
    
    # Pulisci file temporaneo
    if temp_file:
        try:
            os.unlink(temp_file_path)
            logger.debug(f"File temporaneo rimosso: {temp_file_path}")
        except Exception as e:
            logger.warning(f"Impossibile rimuovere file temporaneo {temp_file_path}: {e}")
    
    return True

def attach_file_to_project(project_id, file_path, title):
    cmd = [
        'reptor', '-k', '-p', project_id, 'file', file_path,
        '--notetitle', title,
        '--filename', 'Vulnerability.xlsx'
    ]
    logger.debug(f"Eseguo: {' '.join(cmd)}")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    logger.debug(result.stdout)
    if result.returncode != 0:
        logger.error(f"Errore allegando file alle note: {result.stderr}")
        sys.exit(1)
    return True

def severity_to_int(sev):
    mapping = {'Info': 0, 'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
    return mapping.get(str(sev).capitalize(), 0)

def process_single_file(file_path, args):
    """Processa un singolo file (logica originale del main)"""
    if not os.path.isfile(file_path):
        logger.error(f"{ERROR} Errore: il file {file_path} non esiste.")
        return False
    
    file_type = detect_file_type(file_path, args.type)
    if file_type not in ['burp', 'nessus']:
        logger.error(f"{ERROR} Errore: tipo file non valido per {file_path}. Deve essere: burp, nessus")
        return False
    
    # Configurazione progetto
    today = datetime.date.today().strftime('%Y-%m-%d')
    base_filename = os.path.splitext(os.path.basename(file_path))[0]
    
    if args.extra:
        project_name = f"{today} - {'WEBAPP VA' if file_type == 'burp' else 'VA INFRA'} - {args.client} - {args.extra} - {base_filename}"
    else:
        project_name = f"{today} - {'WEBAPP VA' if file_type == 'burp' else 'VA INFRA'} - {args.client} - {base_filename}"
    
    # Seleziona il design_id in base a lingua e tipo
    if args.lang == 'it':
        design_id = BURP_DESIGN_IT_ID if file_type == 'burp' else NESSUS_DESIGN_IT_ID
    else:
        design_id = BURP_DESIGN_ENG_ID if file_type == 'burp' else NESSUS_DESIGN_ENG_ID
    
    project_type = 'WEBAPP VA' if file_type == 'burp' else 'VA INFRA'
    
    print(SEPARATOR)
    print(f"{STEP} File: {BOLD(file_path)}")
    print(f"{STEP} Tipo rilevato: {BOLD(file_type)}")
    print(f"{STEP} Nome progetto: {BOLD(project_name)}")
    print(f"{STEP} Cliente: {BOLD(args.client)}")
    
    if file_type == 'burp':
        burp_input_format = detect_burp_format(file_path, args.input_format)
        print(f"{STEP} Formato input: {BOLD(burp_input_format)}")
    else:
        burp_input_format = None
    
    print(f"{STEP} Design ID: {BOLD(design_id)}")
    print(f"{STEP} Filtro severità: {BOLD(args.severity)}")
    if args.exclude:
        print(f"{STEP} Plugin IDs esclusi: {BOLD(args.exclude)}")
    
    # Mostra opzioni di aggregazione
    if file_type == 'nessus':
        if args.aggregate:
            print(f"{STEP} Aggregazione vulnerabilità: {BOLD('ATTIVATA')} (Host + Porta + Protocollo + Prodotto)")
        else:
            print(f"{STEP} Aggregazione vulnerabilità: {BOLD('DISATTIVATA')}")
        
        if args.aggregate_excel:
            print(f"{STEP} Aggregazione Excel: {BOLD('ATTIVATA')} (Host + Porta + Protocollo + Prodotto)")
        else:
            print(f"{STEP} Aggregazione Excel: {BOLD('DISATTIVATA')} (Host + Porta + Protocollo + Prodotto)")
    
    print(SEPARATOR)
    
    try:
        # Step 1: Creazione progetto
        print(f"{STEP} Step 1: Creazione nuovo progetto...")
        project_id = create_project(project_name, design_id, project_type, args.client)
        print(f"{SUCCESS} Progetto creato con ID: {BOLD(project_id)}")
        
        # Step 2: Importazione vulnerabilità
        print(f"{STEP} Step 2: Importazione vulnerabilità e push delle finding...")
        if file_type == 'nessus' and args.aggregate:
            print(f"{STEP}   → Aggregazione attiva: vulnerabilità dello stesso prodotto per host/porta/protocollo verranno raggruppate")
        push_findings(file_type, project_id, file_path, args.severity, args.exclude, burp_input_format, aggregate=args.aggregate)
        print(f"{SUCCESS} Importazione completata con successo!")
        
        # Step 3: (Solo Nessus) Generazione Excel e allegato
        if file_type == 'nessus':
            print(f"{STEP} Step 3: Generazione Excel e allegato nelle note...")
            if args.aggregate_excel:
                print(f"{STEP}   → Aggregazione Excel attiva: vulnerabilità dello stesso prodotto per host/porta/protocollo verranno raggruppate")
            script_dir = os.path.dirname(os.path.abspath(__file__))
            safe_filename = "".join(c for c in base_filename if c.isalnum() or c in (' ', '-', '_')).rstrip()
            excel_path = os.path.join(script_dir, f'Vulnerability_{safe_filename}.xlsx')
            num_vulns = nessus_to_excel(file_path, excel_path, args.aggregate_excel)
            print(f"{SUCCESS} Excel generato ({num_vulns} vulnerabilità): {BOLD(excel_path)}")
            attach_file_to_project(project_id, excel_path, "Excel Vulnerabilità Nessus")
            print(f"{SUCCESS} Excel allegato come nota al progetto.")
        
        print(SEPARATOR)
        print(colored('RIEPILOGO', 'yellow', attrs=['bold']))
        print(f"{BOLD('File')}: {file_path}")
        print(f"{BOLD('Tipo')}: {file_type}")
        print(f"{BOLD('Progetto ID')}: {project_id}")
        print(f"{BOLD('Nome')}: {project_name}")
        
        # Link al progetto
        try:
            result = subprocess.run(['reptor', 'conf', '--show'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            server = None
            for line in result.stdout.splitlines():
                if 'server' in line:
                    server = line.split()[1]
                    break
            if server:
                print(f"{BOLD('Link')}: {server}/projects/{project_id}")
        except Exception:
            pass
        
        print(SEPARATOR)
        return True
        
    except Exception as e:
        logger.error(f"{ERROR} Errore durante il processamento di {file_path}: {str(e)}")
        return False

def main():
    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    if args.lang not in ['it', 'eng']:
        logger.error(f"Lingua non valida: {args.lang}. Usa solo 'it' o 'eng'.")
        sys.exit(1)
    check_reptor_installed()
    
    if args.split:
        # Modalità split: processa tutti i file .nessus in una directory
        if not os.path.isdir(args.file):
            logger.error(f"{ERROR} Errore: con --split, --file deve essere una directory. {args.file} non è una directory.")
            sys.exit(1)
        
        # Trova tutti i file .nessus nella directory
        nessus_files = []
        for file in os.listdir(args.file):
            if file.lower().endswith('.nessus'):
                nessus_files.append(os.path.join(args.file, file))
        
        if not nessus_files:
            logger.error(f"{ERROR} Errore: nessun file .nessus trovato nella directory {args.file}")
            sys.exit(1)
        
        print(colored(f'MODALITÀ SPLIT: Processando {len(nessus_files)} file .nessus', 'cyan', attrs=['bold']))
        print(SEPARATOR)
        
        successful = 0
        failed = 0
        
        for i, nessus_file in enumerate(nessus_files, 1):
            print(colored(f'[{i}/{len(nessus_files)}] Processando: {os.path.basename(nessus_file)}', 'yellow', attrs=['bold']))
            
            if process_single_file(nessus_file, args):
                successful += 1
                print(colored(f"✓ File {os.path.basename(nessus_file)} processato con successo", 'green'))
            else:
                failed += 1
                print(colored(f"✗ Errore nel processamento di {os.path.basename(nessus_file)}", 'red'))
            
            print()  # Riga vuota tra i file
        
        # Riepilogo finale
        print(colored('RIEPILOGO FINALE SPLIT', 'yellow', attrs=['bold']))
        print(f"{BOLD('File processati con successo')}: {successful}")
        print(f"{BOLD('File con errori')}: {failed}")
        print(f"{BOLD('Totale file')}: {len(nessus_files)}")
        print(SEPARATOR)
        
        if failed > 0:
            print(colored("Alcuni file non sono stati processati correttamente", 'yellow'))
        else:
            print(colored("Tutti i file sono stati processati con successo", 'green', attrs=['bold']))
        
    else:
        # Modalità standard: processa un singolo file
        success = process_single_file(args.file, args)
        if success:
            print(colored("Il progetto è pronto per la revisione su SysReptor", 'green', attrs=['bold']))
        else:
            sys.exit(1)

if __name__ == "__main__":
    main() 