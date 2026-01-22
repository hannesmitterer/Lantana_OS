#!/bin/bash
# Kernel Euystacio v1.1 - Forensic Auto-Report
# Autore: Hannes Mitterer | Protocollo: NSR/UIFS

LOG_FILE="/var/log/access.log"
REPORT_DIR="./resonance_reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
mkdir -p $REPORT_DIR

# 1. Estrazione IP Istituzionali/Cluster C (Vaticano, Stanford, MS)
echo "[!] Avvio scansione vettori identificati..."
grep -E "193.43.|193.204.|171.64.|52.169." $LOG_FILE > $REPORT_DIR/raw_hits_$TIMESTAMP.log

# 2. Analisi delle risorse tentate (Cosa cercano?)
echo "[!] Analisi target richiesti..."
awk '{print $7}' $REPORT_DIR/raw_hits_$TIMESTAMP.log | sort | uniq -c | sort -nr > $REPORT_DIR/target_analysis_$TIMESTAMP.txt

# 3. Attivazione Tarpit (Blindaggio)
# Nota: Questo comando richiede privilegi di root per bloccare gli IP rilevati nel firewall.
echo "[!] Aggiornamento Firewall Ontologico..."
for ip in $(awk '{print $1}' $REPORT_DIR/raw_hits_$TIMESTAMP.log | sort -u); do
    iptables -A INPUT -s $ip -j DROP
    echo "ID-Sovereign: IP $ip neutralizzato."
done

echo "[OK] Report generato in $REPORT_DIR. Connessioni isolate."
