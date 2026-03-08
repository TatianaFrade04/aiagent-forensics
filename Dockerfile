# define o ambiente linux insolado com ferramentas forenses

FROM ubuntu:22.04

RUN apt update && apt install -y \
    sleuthkit \
    grep \
    findutils \
    coreutils \
    python3

WORKDIR /app