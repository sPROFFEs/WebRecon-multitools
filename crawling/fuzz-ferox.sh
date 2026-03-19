#!/bin/bash
 
TARGET="https://TARGET"
WORDLIST_DIR="/usr/share/seclists/Discovery/Web-Content"
OUTPUT_FILE="ferox_findings.txt"
EXTENSIONS="jsp,json,xml,txt"
THREADS=50
 
echo "--- MASS SCAN START: $(date) ---" > "$OUTPUT_FILE"
echo "Target: $TARGET" >> "$OUTPUT_FILE"
echo "----------------------------------------" >> "$OUTPUT_FILE"
 
echo -e "\n[+] Starting Mass Fuzzing against $TARGET"
echo -e "[+] 200 OK results will be saved to: $OUTPUT_FILE\n"
 
for wordlist in "$WORDLIST_DIR"/*; do
    if [ -f "$wordlist" ]; then
        filename=$(basename "$wordlist")
       
        echo -e "\n========================================================"
        echo -e "[*] Testing wordlist: $filename"
        echo -e "========================================================"
       
        feroxbuster -u "$TARGET" \
            -w "$wordlist" \
            -x "$EXTENSIONS" \
            -t "$THREADS" \
            -k -n \
            -s 200 \ #Aqui filtra los estados, depende de lo que te devuelvan
            --no-state \
            --silent \
            | tee -a "$OUTPUT_FILE"
    fi
done
 
echo -e "\n\n[+] PROCESS FINISHED. Check $OUTPUT_FILE"
