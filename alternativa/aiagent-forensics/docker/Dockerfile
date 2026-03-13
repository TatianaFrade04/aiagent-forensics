FROM ubuntu:22.04

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
    python3 \
    python3-pip \
    md5deep \
    && pip3 install python-evtx evtx \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /forensics_raw /forensics_ewf /forensics

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /root
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]
