# Build: docker build -t forensics-sandbox ./docker
#**Windows (PowerShell): .\build.ps1
#**Linux / macOS (bash): bash build.sh
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    ewf-tools \
    sleuthkit \
    grep \
    findutils \
    file \
    binutils \
    xxd \
    kpartx \
    chntpw \
    qemu-utils \
    ntfs-3g \
    fuse3 \
    python3 \
    python3-pip \
    md5deep \
    sqlite3 \
    libimage-exiftool-perl \
    regripper \
    reglookup \
    && rm -rf /var/lib/apt/lists/*

# Install EVTX parsing tools explicitly with python3 -m pip to guarantee
# the packages land in the same Python that the container runs.
# Verify import works immediately so the build fails visibly if not.
RUN python3 -m pip install --break-system-packages python-evtx evtx \
    && python3 -c "import Evtx.Evtx; print('[+] python-evtx OK')" \
    && python3 -c "import evtx; print('[+] evtx OK')" \
    && EVTXDUMP=$(find /usr /root -name "evtxdump.py" 2>/dev/null | head -1) \
    && [ -n "$EVTXDUMP" ] && ln -sf "$EVTXDUMP" /usr/local/bin/evtxdump.py && echo "[+] evtxdump.py -> $EVTXDUMP" \
    || echo "[-] evtxdump.py not found after install"

RUN mkdir -p /forensics_raw /forensics_ewf /forensics

COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r//' /entrypoint.sh && chmod +x /entrypoint.sh

WORKDIR /root
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/sleep", "infinity"]





#how to run our project

#cd C:\AIAgentForensics
#./build.ps1  -> apenas uma vez ao inicio
#py agent\main.py
