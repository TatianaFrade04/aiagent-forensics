# AIAgent@forensics

**Politécnico de Leiria — ESTG | Licenciatura em Engenharia Informática**  
Projecto Final 2025–2026

Agente LLM com paradigma **ReAct (Reason + Act)** para investigação forense digital.
O agente raciocina autonomamente, executa comandos forenses dentro de um container Docker isolado e gera relatórios detalhados com as fontes de cada descoberta.

---

## Arquitectura

```
Windows (máquina local)
├── Ollama            ← modelo LLM (local ou servidor remoto)
├── Python / LangGraph  ← agente ReAct corre aqui
├── RAG (ChromaDB)    ← índice de documentos PDF
├── evidence/         ← coloca aqui a imagem forense (ou directório extraído)
├── exports/          ← relatórios e ficheiros de output
└── Container Docker (sandbox isolada)
    ├── --network none           (sem internet)
    ├── /forensics_raw/          (imagem original, read-only — modo normal)
    ├── /forensics/              (directório de evidência — modo --no-mount)
    ├── /forensics_ewf/          (mount ewf para E01 → ewf1)
    ├── /forensics/partN/        (partições NTFS montadas automaticamente)
    └── /exports/                (escrita de relatórios e ficheiros)
```

O agente usa um **loop ReAct com janela deslizante**: quando o contexto atinge 70 % de ocupação, comprime o histórico para um relatório intermédio em disco e resume a investigação. A 85 % força a conclusão. Se o modelo terminar com menos de 25 % de contexto usado e ainda houver relatórios intermédios, o agente deteta a terminação prematura e força uma continuação (máx. 3 vezes).

---

## Formatos de evidência suportados

| Formato | Extensão | Ferramenta |
|---------|----------|------------|
| EnCase (single) | `.E01` | ewfmount |
| EnCase (multi-part) | `.E01 .E02 ...` | ewfmount (automático) |
| RAW / DD | `.dd .raw .img` | mount directo |
| Virtual Hard Disk | `.vhd` | qemu-nbd |
| VMware | `.vmdk` | qemu-nbd |
| Directório já extraído | `pasta/` | `--no-mount` |

---

## Instalação

### Pré-requisitos

- [Docker Desktop](https://www.docker.com/products/docker-desktop) (actualizado, a correr)
- [Ollama](https://ollama.com/download) com o modelo desejado: `ollama pull gemma4:e4b`
- [uv](https://docs.astral.sh/uv/) (gestor de pacotes Python recomendado)

### 1. Instalar dependências Python

```bash
uv sync
```

### 2. Colocar a evidência

Imagem forense:
```
evidence/
└── imagem.E01   ← (ou .dd, .vhd, .vmdk)
```

Ou directório já extraído (usar com `--no-mount`):
```
evidence/
└── part006/
    └── USERS/
        └── ...
```

### 3. Configurar o modelo (opcional)

Criar ficheiro `.env` na raiz ou em `agent/`:
```env
OLLAMA_MODEL=gemma4:e4b
OLLAMA_URL=http://localhost:11434
FORENSICS_IMAGE_PATH=./evidence
```

> A imagem Docker (`forensics-sandbox`) é construída automaticamente na primeira execução se não existir.

---

## Utilização

```bash
uv run forensics
```

### Opções da linha de comandos

| Opção | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `--model` | string | `gemma4:e4b` | Modelo Ollama a usar |
| `--url` | string | `http://localhost:11434` | URL do servidor Ollama |
| `--ctx` | int | `32768` | Tamanho do contexto em tokens |
| `--temp` | float | `0.3` | Temperatura do modelo |
| `--dir` | path | `./evidence` | Directório host com a imagem forense |
| `--evidence` | path | auto | Partição dentro do container a usar (ex: `/forensics/part002`) |
| `--no-mount` | flag | — | Monta o directório de evidência directamente em `/forensics` sem tentar montar imagem E01/DD |
| `--no-clear-rag` | flag | — | Mantém documentos RAG indexados de sessões anteriores |
| `--think` | flag | activado | Activa modo de raciocínio do modelo (reasoning) |
| `--debug` | flag | — | Mostra campos raw do AIMessage para inspecção |

### Exemplos

```bash
# Investigação normal com imagem E01
uv run forensics --model gemma4:e4b --ctx 65536

# Modelo noutro servidor
uv run forensics --url http://192.168.1.100:11434 --model gemma4:e4b

# Evidência já extraída como directório
uv run forensics --no-mount

# Reutilizar RAG de sessão anterior
uv run forensics --no-clear-rag
```

### Comandos especiais no chat

| Comando | Acção |
|---------|-------|
| `estrutura` | Mostra o que está montado em `/forensics` |
| `limpar` | Limpa o histórico de conversa |
| `sair` | Termina o programa |

---

## Exemplos de perguntas ao agente

```
Que sistema operativo é este e quando foi instalado?
Quantos utilizadores existem? (filesystem + registo SAM)
Lista os ficheiros do desktop de <username>
Que programas estão instalados no sistema?
Quais os dispositivos USB que foram ligados?
Que chaves de registo estão configuradas para auto-arranque?
Mostra os ficheiros modificados entre 25 e 27 de maio de 2015
Qual é o MD5 do ficheiro suspeito.exe?
Mostra os metadados EXIF de uma fotografia
Identifica websites visitados pelo suspeito (browser history)
Mostra os ficheiros recentemente acedidos (Jump Lists)
Prova que cmd.exe foi executado no sistema (Prefetch)
Procura a palavra "password" em todos os documentos
Faz análise completa de utilizadores, programas instalados, ficheiros recentes e dispositivos USB
```

---

## Sistema de Skills

O agente usa **skills modulares** para injectar conhecimento forense específico no system prompt, apenas quando relevante para a pergunta. Isto poupa contexto e foca o modelo na ferramenta certa.

As skills estão em `skills/*.txt` e são carregadas automaticamente no arranque. Para cada pergunta, o sistema seleciona a skill mais relevante por keyword matching.

| Skill | Ferramenta | Casos de uso |
|-------|-----------|--------------|
| `browser_history` | sqlite3 | Histórico de navegação (Chrome, Firefox, Edge) |
| `exiftool` | ExifTool | Metadados EXIF de imagens e documentos |
| `file_search` | find / grep | Pesquisa de ficheiros por nome, data, conteúdo |
| `jump_lists` | python-libjumplist | Ficheiros acedidos recentemente por aplicação |
| `prefetch` | strings / peparse | Prova de execução de programas |
| `rag` | ChromaDB | Consulta de documentos PDF indexados |
| `recycle_bin` | python / strings | Ficheiros eliminados da Reciclagem |
| `reglookup` | reglookup | Consulta directa a hives do registo Windows |
| `regripper` | RegRipper | Análise forense automatizada do registo |
| `string_search` | strings / grep | Pesquisa de texto em ficheiros binários |
| `timestamps` | find / stat | Timestamps, intervalos de datas, timelines |

Para adicionar uma nova skill, cria um ficheiro `skills/nome.txt` seguindo o formato de `skills/TEMPLATE.txt`. Não é necessária nenhuma alteração de código.

---

## Sistema RAG

O agente inclui um pipeline **RAG (Retrieval-Augmented Generation)** para indexar e consultar documentos PDF (manuais, relatórios forenses, jurisprudência).

- Os PDFs são indexados com embeddings locais (`all-MiniLM-L6-v2`) e guardados em `chroma_store/`
- O agente dispõe de duas ferramentas RAG: `ingest_pdf_document` e `query_rag_documents`
- Por omissão, o índice é limpo no arranque (usar `--no-clear-rag` para manter entre sessões)

---

## Relatórios e output

Todos os relatórios são guardados em `exports/` (montado também em `/exports/` dentro do container):

- **Relatório final** (`export_<timestamp>.txt`) — gerado automaticamente no final de cada investigação, com cabeçalho que inclui o tempo de resposta e a pergunta original
- **Relatórios intermédios** (`intermediate_<n>_<timestamp>.txt`) — criados durante compressão de contexto, consolidados no relatório final
- **Ficheiros de output** — qualquer ficheiro guardado pelo agente em `/exports/` fica disponível em `exports/` no host

Todos os achados incluem a sua **fonte exacta** (caminho completo, hive + chave de registo, ou ficheiro de base de dados + tabela).

---

## Estrutura do projecto

```
aiagent-forensics/
├── agent/
│   ├── main.py          ← agente principal (ReAct loop, compressão de contexto, relatórios)
│   ├── skills.py        ← carregamento e selecção de skills
│   ├── tools.py         ← gestão do container Docker e execução de comandos
│   └── requirements.txt
├── docker/
│   ├── Dockerfile       ← imagem com ferramentas forenses (sleuthkit, ewf, reglookup...)
│   └── entrypoint.sh    ← auto-detecção e montagem de E01/DD/VHD/VMDK
├── rag/
│   ├── config.py        ← configuração centralizada (modelo, chunking, ChromaDB)
│   ├── indexer.py       ← ingestão e chunking de PDFs
│   ├── retriever.py     ← pesquisa semântica no ChromaDB
│   └── generator.py     ← geração de resposta com contexto RAG
├── skills/
│   ├── TEMPLATE.txt     ← template para novas skills
│   ├── browser_history.txt
│   ├── exiftool.txt
│   ├── file_search.txt
│   ├── jump_lists.txt
│   ├── prefetch.txt
│   ├── rag.txt
│   ├── recycle_bin.txt
│   ├── reglookup.txt
│   ├── regripper.txt
│   ├── string_search.txt
│   └── timestamps.txt
├── evidence/            ← coloca aqui a imagem forense ou directório (não commitar)
├── exports/             ← relatórios gerados pelo agente
├── chroma_store/        ← índice RAG persistente (não commitar)
└── pyproject.toml
```

---

## Notas técnicas

- O `entrypoint.sh` detecta automaticamente o tipo de imagem, monta E01 via `ewfmount`, identifica partições com `mmls` e monta cada partição NTFS via `losetup` + driver NTFS do kernel
- Com `--no-mount`, o directório de evidência é montado directamente em `/forensics`; o entrypoint não encontra nenhuma imagem e dorme
- A imagem Docker `forensics-sandbox` é construída automaticamente se não existir (`docker build -t forensics-sandbox ./docker`)
- Output acima de 100 linhas é guardado em `/tmp/` dentro do container; o agente recebe as primeiras 100 linhas e instruções para usar `grep`/`head`
- Compressão de contexto: a 70 % de ocupação, o histórico é comprimido para relatório intermédio em disco; a 85 % o agente é forçado a concluir
- Detecção de terminação prematura: se o agente terminar com < 25 % de contexto e existirem relatórios intermédios, é forçada uma continuação (máx. 3 vezes)
- A listagem de utilizadores Windows cruza sempre duas fontes: directório `USERS/` (filesystem) e chave `/SAM/Domains/Account/Users/Names` (registo SAM)

---

## Orientadores

- Miguel Negrão — miguel.negrao@ipleiria.pt
- Miguel Frade — miguel.frade@ipleiria.pt
- Patrício Domingues — patricio.domingues@ipleiria.pt
