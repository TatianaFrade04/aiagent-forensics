#!/bin/bash
# =============================================================================
# AIAgent@forensics — Auto-mount entrypoint
# Suporta: .E01/.Ex01 (single e multi-part), .dd/.raw/.img, .vhd, .vmdk
# =============================================================================

FORENSICS_RAW="/forensics_raw"
EWF_MOUNT="/forensics_ewf"
FINAL_MOUNT="/forensics"
INFO_FILE="/forensics_info.txt"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║        AIAgent@forensics v1.0            ║"
echo "║   Politécnico de Leiria — ESTG           ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "[*] A procurar imagens forenses em $FORENSICS_RAW..."

# ─── Detecta o tipo de imagem ─────────────────────────────────────────────────

E01_FILE=$(find "$FORENSICS_RAW" -maxdepth 2 \( -iname "*.E01" -o -iname "*.Ex01" \) | sort | head -1)
RAW_FILE=$(find "$FORENSICS_RAW" -maxdepth 2 \( -iname "*.dd" -o -iname "*.raw" -o -iname "*.img" \) | sort | head -1)
VHD_FILE=$(find "$FORENSICS_RAW" -maxdepth 2 -iname "*.vhd" | sort | head -1)
VMDK_FILE=$(find "$FORENSICS_RAW" -maxdepth 2 -iname "*.vmdk" | sort | head -1)

RAW_DEVICE=""

# ─── Monta conforme o tipo ────────────────────────────────────────────────────

if [ -n "$E01_FILE" ]; then
    echo "[*] Encontrado E01: $E01_FILE"
    SEGMENT_COUNT=$(find "$FORENSICS_RAW" -maxdepth 2 \( -iname "*.E??" -o -iname "*.Ex??" \) | wc -l)
    if [ "$SEGMENT_COUNT" -gt 1 ]; then
        echo "[*] Imagem multi-part detectada ($SEGMENT_COUNT segmentos)"
    fi
    ewfmount "$E01_FILE" "$EWF_MOUNT"
    if [ $? -ne 0 ]; then
        echo "[!] Erro ao montar E01 com ewfmount."
        exit 1
    fi
    RAW_DEVICE="$EWF_MOUNT/ewf1"
    echo "[+] E01 montado em $EWF_MOUNT"

elif [ -n "$RAW_FILE" ]; then
    echo "[*] Encontrado RAW/DD: $RAW_FILE"
    RAW_DEVICE="$RAW_FILE"

elif [ -n "$VHD_FILE" ]; then
    echo "[*] Encontrado VHD: $VHD_FILE"
    modprobe nbd max_part=8 2>/dev/null
    qemu-nbd --connect=/dev/nbd0 --read-only "$VHD_FILE"
    RAW_DEVICE="/dev/nbd0"

elif [ -n "$VMDK_FILE" ]; then
    echo "[*] Encontrado VMDK: $VMDK_FILE"
    modprobe nbd max_part=8 2>/dev/null
    qemu-nbd --connect=/dev/nbd0 --read-only "$VMDK_FILE"
    RAW_DEVICE="/dev/nbd0"

else
    echo "[!] Nenhuma imagem forense encontrada."
    exec "$@"
fi

# ─── Detecta partições e guarda offsets ──────────────────────────────────────

echo ""
echo "=== Tabela de partições ==="
mmls "$RAW_DEVICE" 2>/dev/null || echo "(não foi possível ler tabela de partições)"

# Guarda info para o agente consultar
echo "RAW_DEVICE=$RAW_DEVICE" > "$INFO_FILE"
echo "" >> "$INFO_FILE"
echo "=== TABELA DE PARTICOES ===" >> "$INFO_FILE"
mmls "$RAW_DEVICE" 2>/dev/null >> "$INFO_FILE"

# ─── Garante loop devices disponíveis ────────────────────────────────────────

# Cria loop devices se não existirem e limpa stale do container anterior
for i in $(seq 2 8); do
    [ -e /dev/loop$i ] || mknod /dev/loop$i b 7 $i 2>/dev/null
done
# Liberta loop devices stale (não associados a ficheiros acessíveis)
losetup -D 2>/dev/null

# ─── Tenta montar partições via losetup ──────────────────────────────────────

echo ""
echo "[*] A tentar montar partições..."

MOUNTED=0

# Extrai linhas de partições reais (ignora Meta, Unallocated)
while IFS= read -r line; do
    [ -z "$line" ] && continue

    PART_NUM=$(echo "$line" | awk '{print $1}' | tr -d ':')
    START=$(echo "$line" | awk '{print $3}')
    LENGTH=$(echo "$line" | awk '{print $5}')

    [ -z "$START" ] && continue
    START_DEC=$(echo "$START" | sed 's/^0*//' | tr -d ' ')
    [ -z "$START_DEC" ] && continue
    [ "$START_DEC" = "0" ] && continue

    LENGTH_DEC=$(echo "$LENGTH" | sed 's/^0*//')
    [ -z "$LENGTH_DEC" ] && LENGTH_DEC=0

    OFFSET_BYTES=$((START_DEC * 512))
    SIZE_BYTES=$((LENGTH_DEC * 512))
    MOUNT_POINT="$FINAL_MOUNT/part$PART_NUM"
    mkdir -p "$MOUNT_POINT"

    # Usa losetup --find --show para obter e configurar loop device automaticamente
    LOOP_DEV=$(losetup --find --show -o "$OFFSET_BYTES" --sizelimit "$SIZE_BYTES" --read-only "$RAW_DEVICE" 2>/dev/null)

    if [ -z "$LOOP_DEV" ]; then
        echo "[!] Partição $PART_NUM: sem loop devices disponíveis"
        echo "PART_${PART_NUM}_OFFSET=$OFFSET_BYTES" >> "$INFO_FILE"
        rmdir "$MOUNT_POINT" 2>/dev/null
        continue
    fi

    if mount -t ntfs -o ro "$LOOP_DEV" "$MOUNT_POINT" 2>/dev/null; then
        echo "[+] Partição $PART_NUM montada em $MOUNT_POINT (NTFS via $LOOP_DEV)"
        echo "PART_${PART_NUM}_MOUNT=$MOUNT_POINT" >> "$INFO_FILE"
        echo "PART_${PART_NUM}_OFFSET=$OFFSET_BYTES" >> "$INFO_FILE"
        MOUNTED=$((MOUNTED + 1))
    elif mount -o ro "$LOOP_DEV" "$MOUNT_POINT" 2>/dev/null; then
        echo "[+] Partição $PART_NUM montada em $MOUNT_POINT (auto via $LOOP_DEV)"
        echo "PART_${PART_NUM}_MOUNT=$MOUNT_POINT" >> "$INFO_FILE"
        echo "PART_${PART_NUM}_OFFSET=$OFFSET_BYTES" >> "$INFO_FILE"
        MOUNTED=$((MOUNTED + 1))
    else
        echo "[!] Partição $PART_NUM: loop device criado mas mount falhou ($LOOP_DEV)"
        losetup -d "$LOOP_DEV" 2>/dev/null
        echo "PART_${PART_NUM}_OFFSET=$OFFSET_BYTES" >> "$INFO_FILE"
        rmdir "$MOUNT_POINT" 2>/dev/null
    fi

done < <(mmls "$RAW_DEVICE" 2>/dev/null | grep -E "^\s*[0-9]+" | grep -iv "Unallocated\|Meta\|GPT\|MBR\|Safety\|Empty")

# ─── Resumo ───────────────────────────────────────────────────────────────────

echo ""
echo "=== Resumo ==="
echo "RAW_DEVICE: $RAW_DEVICE" 

if [ "$MOUNTED" -gt 0 ]; then
    echo "[+] $MOUNTED partição(ões) montada(s) com sucesso!"
    echo "[+] Ficheiros acessíveis em /forensics:"
    ls /forensics/
else
    echo "[!] Montagem directa não foi possível (normal em alguns containers)."
    echo "[!] O agente pode usar fls/icat directamente sobre $RAW_DEVICE"
    echo "[!] Exemplo: fls -r $RAW_DEVICE"
fi

echo ""
echo "[+] Container pronto."
echo ""

exec "$@"