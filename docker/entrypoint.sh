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

# ─── Cleanup helper ──────────────────────────────────────────────────────────

cleanup_partition() {
    local loop_dev="$1"
    local mount_point="$2"
    [ -n "$loop_dev" ]    && losetup -d "$loop_dev"  2>/dev/null
    [ -d "$mount_point" ] && rmdir    "$mount_point" 2>/dev/null
}

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║        AIAgent@forensics v1.0            ║"
echo "║   Politécnico de Leiria — ESTG           ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ─── Verifica capabilities necessárias ───────────────────────────────────────
# CAP_SYS_ADMIN = bit 21 = 0x200000; lê directamente de /proc/self/status (sem capsh)
CAP_EFF=$(grep '^CapEff:' /proc/self/status | awk '{print $2}')
if [ $(( 16#${CAP_EFF} & 16#200000 )) -eq 0 ]; then
    echo "[!] ERRO FATAL: cap_sys_admin não detectada — mount e losetup vão falhar."
    echo "[!] Adiciona ao docker run: --cap-add SYS_ADMIN --cap-add MKNOD --device /dev/loop-control --device /dev/fuse --device-cgroup-rule 'b 7:* rmw'"
    exit 1
fi

# Verifica /dev/fuse (necessário para ewfmount)
if [ ! -c /dev/fuse ]; then
    echo "[!] ERRO FATAL: /dev/fuse não encontrado — ewfmount vai falhar."
    echo "[!] Adiciona ao docker run: --device /dev/fuse"
    exit 1
fi

# Verifica /dev/loop-control (necessário para losetup --find)
if [ ! -c /dev/loop-control ]; then
    echo "[!] ERRO FATAL: /dev/loop-control não encontrado — losetup vai falhar."
    echo "[!] Adiciona ao docker run: --device /dev/loop-control --device-cgroup-rule 'b 7:* rmw'"
    exit 1
fi

echo "[*] A procurar imagens forenses em $FORENSICS_RAW..."

# ─── Detecta o tipo de imagem ─────────────────────────────────────────────────

E01_FILE=$(find "$FORENSICS_RAW" -maxdepth 2 \( -iname "*.E01" -o -iname "*.Ex01" \) | sort | head -1)
RAW_FILE=$(find "$FORENSICS_RAW" -maxdepth 2 \( -iname "*.dd" -o -iname "*.raw" -o -iname "*.img" \) | sort | head -1)
VHD_FILE=$(find "$FORENSICS_RAW" -maxdepth 2 -iname "*.vhd" | sort | head -1)
VMDK_FILE=$(find "$FORENSICS_RAW" -maxdepth 2 -iname "*.vmdk" | sort | head -1)

RAW_DEVICE=""

# ─── Monta conforme o tipo  (nivel 1)────────────────────────────────────────────────────

if [ -n "$E01_FILE" ]; then
    echo "[*] Encontrado E01: $E01_FILE"
    SEGMENT_COUNT=$(find "$FORENSICS_RAW" -maxdepth 2 \( -iname "*.E??" -o -iname "*.Ex??" \) | wc -l)
    [ "$SEGMENT_COUNT" -gt 1 ] && echo "[*] Imagem multi-part detectada ($SEGMENT_COUNT segmentos)"
    EWFMOUNT_ERR=$(ewfmount "$E01_FILE" "$EWF_MOUNT" 2>&1) #captura o erro
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

# ─── ler Tabela de partições (nivel 2)─────────────────────────────────────────────────────

echo ""
echo "=== Tabela de partições ==="

MMLS_OUTPUT=$(mmls "$RAW_DEVICE" 2>/dev/null)
FDISK_OUTPUT=""

if [ -n "$MMLS_OUTPUT" ]; then
    echo "[+] Tabela lida via mmls:"
    echo "$MMLS_OUTPUT"
else
    echo "[!] mmls falhou — a tentar fdisk -l como fallback..."
    FDISK_OUTPUT=$(fdisk -l "$RAW_DEVICE" 2>/dev/null)
    if [ -n "$FDISK_OUTPUT" ]; then
        echo "[+] Tabela lida via fdisk -l:"
        echo "$FDISK_OUTPUT"
    else
        echo "[!] Nem mmls nem fdisk -l conseguiram ler a tabela de partições."
    fi
fi

# Guarda info base
{
    echo "RAW_DEVICE=$RAW_DEVICE"
    echo ""
    echo "=== TABELA DE PARTICOES ==="
    [ -n "$MMLS_OUTPUT" ] && echo "$MMLS_OUTPUT" || echo "$FDISK_OUTPUT"
} > "$INFO_FILE"

# ─── Garante loop devices disponíveis ────────────────────────────────────────

# Descobre o próximo loop livre e garante que o device node existe
NEXT_LOOP=$(losetup -f 2>/dev/null)
if [ -n "$NEXT_LOOP" ]; then
    LOOP_NUM=${NEXT_LOOP##/dev/loop}
    [ -e "$NEXT_LOOP" ] || mknod "$NEXT_LOOP" b 7 "$LOOP_NUM" 2>/dev/null
fi

# ─── Monta cada uma das partições (nivel 3)────────────────────────────────────────────────────────

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

    echo "[*] Partição $SLOT — start_sector=${START} → offset=${OFFSET_BYTES}B (${START}×${SECTOR_SIZE}), size=${SIZE_BYTES}B"
    echo "PART_${SLOT}_OFFSET=$OFFSET_BYTES" >> "$INFO_FILE"

    # Obtém loop device automaticamente
    LOOP_DEV=$(losetup --find --show \
        -o "$OFFSET_BYTES" \
        --sizelimit "$SIZE_BYTES" \
        --read-only "$RAW_DEVICE" 2>/dev/null)

    if [ -z "$LOOP_DEV" ]; then
        echo "[!] Partição $SLOT: não foi possível criar loop device"
        cleanup_partition "" "$MOUNT_POINT"
        continue
    fi

    echo "[*] Loop device: $LOOP_DEV"

    # Detecta o filesystem com file -s e ordena as tentativas pelo tipo detectado
    FS_HINT=$(file -s "$LOOP_DEV" 2>/dev/null)
    echo "[*] Tipo detectado: $FS_HINT"
    if echo "$FS_HINT" | grep -qi "ntfs"; then
        FS_ORDER="ntfs-3g ntfs3 ntfs ext4 ext3 ext2 vfat auto"
    elif echo "$FS_HINT" | grep -qi "ext4"; then
        FS_ORDER="ext4 ext3 ext2 ntfs-3g ntfs3 ntfs vfat auto"
    elif echo "$FS_HINT" | grep -qi "ext3"; then
        FS_ORDER="ext3 ext4 ext2 ntfs-3g ntfs3 ntfs vfat auto"
    elif echo "$FS_HINT" | grep -qi "ext2"; then
        FS_ORDER="ext2 ext3 ext4 ntfs-3g ntfs3 ntfs vfat auto"
    elif echo "$FS_HINT" | grep -qiE "fat|mkdosfs"; then
        FS_ORDER="vfat ntfs-3g ntfs3 ntfs ext4 ext3 ext2 auto"
    else
        FS_ORDER="ntfs-3g ntfs3 ntfs ext4 ext3 ext2 vfat auto"
    fi

    MOUNT_OK=0
    for FS in $FS_ORDER; do
        if [ "$FS" = "ntfs-3g" ]; then
            MOUNT_OUT=$(mount -t ntfs-3g -o ro,norecovery "$LOOP_DEV" "$MOUNT_POINT" 2>&1)
        elif [ "$FS" = "auto" ]; then
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
        cleanup_partition "$LOOP_DEV" "$MOUNT_POINT"
    fi

done < <(echo "$MMLS_OUTPUT" | grep -E "^\s*[0-9]")

# ─── Fallback: monta via fdisk -l se mmls não produziu partições ─────────────

if [ "$MOUNTED" -eq 0 ] && [ -n "$FDISK_OUTPUT" ]; then
    echo ""
    echo "[*] A tentar montar partições via offsets fdisk..."
    SLOT=1

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        echo "$line" | grep -qE "^(Disk |Device|Disklabel|Units|Sector|I/O)" && continue
        echo "$line" | grep -qE "^\S" || continue

        # fdisk: Device [Boot] Start End Sectors Size [Id Type]
        # Se $2 == "*" (bootável): Start=$3, Sectors=$5; senão: Start=$2, Sectors=$4
        BOOT=$(echo "$line" | awk '{print $2}')
        if [ "$BOOT" = "*" ]; then
            START=$(echo "$line"  | awk '{print $3}' | sed 's/^0*//')
            LENGTH=$(echo "$line" | awk '{print $5}' | sed 's/^0*//')
        else
            START=$(echo "$line"  | awk '{print $2}' | sed 's/^0*//')
            LENGTH=$(echo "$line" | awk '{print $4}' | sed 's/^0*//')
        fi

        [[ "$START"  =~ ^[0-9]+$ ]] || continue
        [[ "$LENGTH" =~ ^[0-9]+$ ]] || continue
        [ "$START"  -eq 0 ] 2>/dev/null && continue
        [ "$LENGTH" -eq 0 ] 2>/dev/null && continue

        OFFSET_BYTES=$(( START  * SECTOR_SIZE ))
        SIZE_BYTES=$(( LENGTH * SECTOR_SIZE ))
        MOUNT_POINT="$FINAL_MOUNT/part${SLOT}"
        mkdir -p "$MOUNT_POINT"

        echo "[*] Partição $SLOT (fdisk) — start_sector=${START} → offset=${OFFSET_BYTES}B (${START}×${SECTOR_SIZE}), size=${SIZE_BYTES}B"
        echo "PART_${SLOT}_OFFSET=$OFFSET_BYTES" >> "$INFO_FILE"

        LOOP_DEV=$(losetup --find --show \
            -o "$OFFSET_BYTES" \
            --sizelimit "$SIZE_BYTES" \
            --read-only "$RAW_DEVICE" 2>/dev/null)

        if [ -z "$LOOP_DEV" ]; then
            echo "[!] Partição $SLOT: não foi possível criar loop device"
            cleanup_partition "" "$MOUNT_POINT"
            SLOT=$(( SLOT + 1 ))
            continue
        fi

        echo "[*] Loop device: $LOOP_DEV"

        # Detecta o filesystem com file -s e ordena as tentativas pelo tipo detectado
        FS_HINT=$(file -s "$LOOP_DEV" 2>/dev/null)
        echo "[*] Tipo detectado: $FS_HINT"
        if echo "$FS_HINT" | grep -qi "ntfs"; then
            FS_ORDER="ntfs-3g ntfs ext4 ext3 ext2 vfat auto"
        elif echo "$FS_HINT" | grep -qi "ext4"; then
            FS_ORDER="ext4 ext3 ext2 ntfs-3g ntfs vfat auto"
        elif echo "$FS_HINT" | grep -qi "ext3"; then
            FS_ORDER="ext3 ext4 ext2 ntfs-3g ntfs vfat auto"
        elif echo "$FS_HINT" | grep -qi "ext2"; then
            FS_ORDER="ext2 ext3 ext4 ntfs-3g ntfs vfat auto"
        elif echo "$FS_HINT" | grep -qiE "fat|mkdosfs"; then
            FS_ORDER="vfat ntfs-3g ntfs ext4 ext3 ext2 auto"
        else
            FS_ORDER="ntfs-3g ntfs ext4 ext3 ext2 vfat auto"
        fi

        MOUNT_OK=0
        for FS in $FS_ORDER; do
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
            cleanup_partition "$LOOP_DEV" "$MOUNT_POINT"
        fi

        SLOT=$(( SLOT + 1 ))
    done < <(echo "$FDISK_OUTPUT")
fi

# ─── Fallback: sem tabela de partições — monta RAW_DEVICE directamente ────────
# Nota: losetup falha em ficheiros FUSE (ewf1). Usamos "mount -o loop" que
# usa um caminho kernel diferente (sem O_DIRECT explícito).

if [ "$MOUNTED" -eq 0 ] && [ -n "$RAW_DEVICE" ]; then
    echo ""
    echo "[*] No partition table detected — trying direct filesystem mount..."
    MOUNT_POINT="$FINAL_MOUNT/part0"
    mkdir -p "$MOUNT_POINT"

    FS_HINT=$(file -s "$RAW_DEVICE" 2>/dev/null)
    echo "[*] Detected type: $FS_HINT"

    if echo "$FS_HINT" | grep -qi "ext4"; then
        FS_ORDER="ext4 ext3 ext2"
    elif echo "$FS_HINT" | grep -qi "ext3"; then
        FS_ORDER="ext3 ext4 ext2"
    elif echo "$FS_HINT" | grep -qi "ext2"; then
        FS_ORDER="ext2 ext3 ext4"
    elif echo "$FS_HINT" | grep -qi "ntfs"; then
        FS_ORDER="ntfs-3g"
    else
        FS_ORDER="ext4 ext3 ext2 ntfs-3g vfat"
    fi

    MOUNT_OK=0
    for FS in $FS_ORDER; do
        if [ "$FS" = "ntfs-3g" ]; then
            MOUNT_OUT=$(mount -t ntfs-3g -o ro,norecovery,loop "$RAW_DEVICE" "$MOUNT_POINT" 2>&1)
        elif [ "$FS" = "ext3" ]; then
            MOUNT_OUT=$(mount -t ext3 -o ro,noload,loop "$RAW_DEVICE" "$MOUNT_POINT" 2>&1)
        elif [ "$FS" = "ext4" ]; then
            MOUNT_OUT=$(mount -t ext4 -o ro,norecovery,loop "$RAW_DEVICE" "$MOUNT_POINT" 2>&1)
        else
            MOUNT_OUT=$(mount -t "$FS" -o ro,loop "$RAW_DEVICE" "$MOUNT_POINT" 2>&1)
        fi
        if [ $? -eq 0 ]; then
            echo "[+] Direct mount at $MOUNT_POINT (fs=$FS)"
            echo "PART_0_MOUNT=$MOUNT_POINT" >> "$INFO_FILE"
            echo "PART_0_FS=$FS" >> "$INFO_FILE"
            MOUNT_OK=1
            MOUNTED=1
            break
        else
            echo "[!] mount -t $FS failed: $MOUNT_OUT"
        fi
    done

    if [ "$MOUNT_OK" -eq 0 ]; then
        echo "[!] All filesystems failed. Check errors above."
        rmdir "$MOUNT_POINT" 2>/dev/null
    fi
fi

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

# Executa o CMD passado (por omissão: /bin/sleep infinity)
# Garante que o container não termina mesmo que CMD seja omitido.
if [ $# -gt 0 ]; then
    exec "$@"
else
    exec /bin/sleep infinity
fi
