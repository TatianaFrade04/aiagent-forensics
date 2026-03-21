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
    && pip3 install --break-system-packages python-evtx evtx \
    && rm -rf /var/lib/apt/lists/*

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
