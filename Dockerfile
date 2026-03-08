# define o ambiente linux insolado com ferramentas forenses

FROM ubuntu:22.04

RUN apt update && apt install -y \
    sleuthkit \
    grep \
    findutils \
    coreutils \
    python3 \
    python3-pip \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instalar dependências Python
COPY requirements.txt /app/requirements.txt
RUN python3 -m pip install --no-cache-dir -r /app/requirements.txt

# Copiar o código do projeto (agente + tools)
COPY agent/ /app/agent/
COPY tools/ /app/tools/

# (opcional mas recomendado) garantir que são packages Python
# Se já tens __init__.py no repo, isto é redundante, mas não faz mal:
RUN touch /app/agent/__init__.py /app/tools/__init__.py

# Entry-point: correr o agente LangChain
CMD ["python3", "-m", "agent.llm_langchain"]