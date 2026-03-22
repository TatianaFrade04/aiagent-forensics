#!/bin/bash
# =============================================================================
# AIAgent@forensics — Auto-mount entrypoint
# Suporta: .E01/.Ex01 (single e multi-part), .dd/.raw/.img, .vhd, .vmdk
# =============================================================================

FORENSICS_RAW="/forensics_raw"
EWF_MOUNT="/forensics_ewf"
FINAL_MOUNT="/forensics"
INFO_FILE="/forensics_info.txt"
SECTOR_SIZE=512

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║        AIAgent@forensics v1.0            ║"
echo "║   Politécnico de Leiria — ESTG           ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ─── Verifica capabilities necessárias ───────────────────────────────────────
# mount e losetup precisam de SYS_ADMIN; sem --privileged tem de ser declarado
# explicitamente via --cap-add SYS_ADMIN --cap-add MKNOD no docker run/compose.
if ! capsh --print 2>/dev/null | grep -q "cap_sys_admin"; then
    echo "[!] AVISO: cap_sys_admin não detectada."
    echo "[!] Adiciona ao docker run: --cap-add SYS_ADMIN --cap-add MKNOD --device /dev/loop-control"
    echo "[!] O agente continuará mas a montagem directa pode falhar."
fi

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
    [ "$SEGMENT_COUNT" -gt 1 ] && echo "[*] Imagem multi-part detectada ($SEGMENT_COUNT segmentos)"
    EWFMOUNT_ERR=$(ewfmount "$E01_FILE" "$EWF_MOUNT" 2>&1)
    if [ $? -ne 0 ]; then
        echo "[!] Erro ao montar E01 com ewfmount: $EWFMOUNT_ERR"
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
    echo "[!] Nenhuma imagem forense encontrada em $FORENSICS_RAW."
    exec "$@"
fi

# ─── Tabela de partições ──────────────────────────────────────────────────────

echo ""
echo "=== Tabela de partições ==="
MMLS_OUTPUT=$(mmls "$RAW_DEVICE" 2>/dev/null)
if [ -z "$MMLS_OUTPUT" ]; then
    echo "[!] mmls não conseguiu ler a tabela de partições."
else
    echo "$MMLS_OUTPUT"
fi

# Guarda info base
{
    echo "RAW_DEVICE=$RAW_DEVICE"
    echo ""
    echo "=== TABELA DE PARTICOES ==="
    echo "$MMLS_OUTPUT"
} > "$INFO_FILE"

# ─── Garante loop devices disponíveis ────────────────────────────────────────

for i in $(seq 0 15); do
    [ -e /dev/loop$i ] || mknod /dev/loop$i b 7 $i 2>/dev/null
done
# Liberta loop devices stale
losetup -D 2>/dev/null

# ─── Monta partições ─────────────────────────────────────────────────────────

echo ""
echo "[*] A tentar montar partições..."
MOUNTED=0

# O formato do mmls é (exemplo DOS):
#   000:  Meta  0000000000  0000000000  0000000001  Primary Table (#0)
#   001:  -----  0000000000  0000062499  0000062500  Unallocated
#   002:  00:00  0000002048  0000206847  0000204800  NTFS (0x07)
#
# Colunas: SLOT | ATTRIB | START | END | LENGTH | DESC
# Usamos: $1=slot  $3=start  $5=length
# ATENÇÃO: o separador pode ser múltiplos espaços; usamos awk com campos fixos.

while IFS= read -r line; do
    [ -z "$line" ] && continue

    # Ignora linhas de cabeçalho/meta/unallocated
    echo "$line" | grep -qiE "Unallocated|Meta|GPT Header|MBR|Safety LBA|Empty|Table" && continue

    # Extrai campos: slot, start, end, length
    # mmls alinha em colunas de largura fixa; awk -v FIELDWIDTHS não é universal,
    # por isso normalizamos os espaços e usamos campos posicionais.
    SLOT=$(echo "$line"   | awk '{gsub(/:$/,"",$1); print $1}')
    START=$(echo "$line"  | awk '{print $3}' | sed 's/^0*//')
    LENGTH=$(echo "$line" | awk '{print $5}' | sed 's/^0*//')

    # Valida que START e LENGTH são números
    [[ "$START"  =~ ^[0-9]+$ ]] || continue
    [[ "$LENGTH" =~ ^[0-9]+$ ]] || continue
    [ "$START"  -eq 0 ] 2>/dev/null && continue
    [ "$LENGTH" -eq 0 ] 2>/dev/null && continue

    OFFSET_BYTES=$(( START  * SECTOR_SIZE ))
    SIZE_BYTES=$(( LENGTH * SECTOR_SIZE ))
    MOUNT_POINT="$FINAL_MOUNT/part${SLOT}"
    mkdir -p "$MOUNT_POINT"

    echo "[*] Partição $SLOT — offset=${OFFSET_BYTES}B, size=${SIZE_BYTES}B"
    echo "PART_${SLOT}_OFFSET=$OFFSET_BYTES" >> "$INFO_FILE"

    # Obtém loop device automaticamente
    LOOP_DEV=$(losetup --find --show \
        -o "$OFFSET_BYTES" \
        --sizelimit "$SIZE_BYTES" \
        --read-only "$RAW_DEVICE" 2>/dev/null)

    if [ -z "$LOOP_DEV" ]; then
        echo "[!] Partição $SLOT: não foi possível criar loop device"
        rmdir "$MOUNT_POINT" 2>/dev/null
        continue
    fi

    echo "[*] Loop device: $LOOP_DEV"

    # 1 Tenta montar por ordem de preferência de filesystem
    MOUNT_OK=0
    for FS in ntfs-3g ntfs ext4 ext3 ext2 vfat auto; do
        if [ "$FS" = "auto" ]; then
            MOUNT_OUT=$(mount -o ro "$LOOP_DEV" "$MOUNT_POINT" 2>&1)
        else
            MOUNT_OUT=$(mount -t "$FS" -o ro "$LOOP_DEV" "$MOUNT_POINT" 2>&1)
        fi
        if [ $? -eq 0 ]; then
            echo "[+] Partição $SLOT montada em $MOUNT_POINT (fs=$FS)"
            {
                echo "PART_${SLOT}_MOUNT=$MOUNT_POINT"
                echo "PART_${SLOT}_FS=$FS"
            } >> "$INFO_FILE"
            MOUNT_OK=1
            MOUNTED=$(( MOUNTED + 1 ))
            break
        fi
    done

    if [ "$MOUNT_OK" -eq 0 ]; then
        echo "[!] Partição $SLOT: mount falhou em todos os filesystems ($MOUNT_OUT)"
        echo "[!] Offset disponível para uso directo com fls/icat: $OFFSET_BYTES"
        losetup -d "$LOOP_DEV" 2>/dev/null
        rmdir "$MOUNT_POINT" 2>/dev/null
    fi

done < <(echo "$MMLS_OUTPUT" | grep -E "^\s*[0-9]")

# ─── Resumo ───────────────────────────────────────────────────────────────────

echo ""
echo "=== Resumo ==="
echo "RAW_DEVICE : $RAW_DEVICE"

if [ "$MOUNTED" -gt 0 ]; then
    echo "[+] $MOUNTED partição(ões) montada(s) com sucesso!"
    echo "[+] Ficheiros acessíveis em $FINAL_MOUNT:"
    ls "$FINAL_MOUNT/"
else
    echo "[!] Nenhuma partição montada directamente."
    echo "[!] O agente pode usar ferramentas do Sleuth Kit directamente:"
    echo "    fls -r $RAW_DEVICE"
    echo "    fls -r -o <offset_sectores> $RAW_DEVICE"
    echo "    icat -o <offset_sectores> $RAW_DEVICE <inode>"
fi

echo ""
echo "[+] Container pronto. Info em $INFO_FILE"
echo ""

exec "$@"
