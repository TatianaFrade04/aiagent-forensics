#!/bin/bash

# Nome do ficheiro exatamente como queres (Ex: diagnostico_dia_07-05_17-45.log)
LOG_FILE="diagnostico_dia_$(date +%d-%m_%H-%M).log"

echo "==========================================================" > $LOG_FILE
echo "INÍCIO DA MONITORIZAÇÃO: $(date '+%d/%m/%Y %H:%M:%S')" >> $LOG_FILE
echo "==========================================================" >> $LOG_FILE

while true; do
    # Checkpoint com data legível: 07/05/2026 17:45:00
    TIMESTAMP=$(date "+%d/%m/%Y %H:%M:%S")
    
    echo "--- CHECKPOINT: $TIMESTAMP ---" >> $LOG_FILE

    echo "[DOCKER STATS]" >> $LOG_FILE
    docker stats --no-stream --format "ID: {{.ID}} | Nome: {{.Name}} | CPU: {{.CPUPerc}} | Mem: {{.MemUsage}}" >> $LOG_FILE

    echo "[HOST RAM]" >> $LOG_FILE
    free -h >> $LOG_FILE

    echo "[LOOP DEVICES]" >> $LOG_FILE
    losetup -a >> $LOG_FILE
    
    echo "[KERNEL ERRORS]" >> $LOG_FILE
    # OOM kills, I/O errors, loop/FUSE failures — exclui mensagens "not found" (ruído FUSE normal)
    sudo dmesg --since="6 minutes ago" 2>/dev/null \
        | grep -Ei "oom kill|out of memory|killed process|i/o error|blk.*error|loop.*fail|loop.*error|fuse.*error|ext[234].*error|kernel panic|hardware error|mce:|machine check|bad sector|disk error|scsi error" \
        | grep -vi "not found|no such file|no such entry|not exist" \
        >> $LOG_FILE

    echo -e "----------------------------------------------------------\n" >> $LOG_FILE

    # Espera 5 minutos
    sleep 300
done