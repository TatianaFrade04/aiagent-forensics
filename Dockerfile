# Container Linux isolado apenas com ferramentas forenses (sleuthkit)
# O código Python corre no Windows — este container expõe só os binários forenses

FROM ubuntu:22.04

RUN apt update && apt install -y \
    sleuthkit \
    grep \
    findutils \
    coreutils \
 && rm -rf /var/lib/apt/lists/*

# Pasta onde o ficheiro .E01 será montado via volume
WORKDIR /evidence

# Manter o container em execução para receber comandos via docker exec
CMD ["sleep", "infinity"]