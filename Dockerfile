# Container Linux isolado apenas com ferramentas forenses (sleuthkit)
# O código Python corre no Windows — este container expõe só os binários forenses

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    sleuthkit \
    grep \
    findutils \
    coreutils \
    libhivex-bin \
    python3 \
    python3-pip \
 && pip3 install --no-cache-dir python-registry python-evtx \
 && rm -rf /var/lib/apt/lists/*

# Pasta onde o ficheiro .E01 será montado via volume
WORKDIR /evidence

# Manter o container em execução para receber comandos via docker exec
CMD ["sleep", "infinity"]