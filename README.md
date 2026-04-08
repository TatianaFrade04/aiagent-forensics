# AIAgent@forensics

**Politécnico de Leiria — ESTG | Licenciatura em Engenharia Informática**
Projecto Final 2025–2026

Agente LLM com paradigma **ReAct (Reason + Act)** para investigação forense digital.
O agente raciocina autonomamente e executa comandos forenses dentro de um container Docker isolado.

---

## Arquitectura

```
Windows (máquina local)
├── Ollama  ← modelo LLM corre aqui
├── Python/LangChain  ← agente corre aqui
├── evidence/  ← coloca aqui a imagem forense
└── Container Docker (sandbox isolada)
    ├── --network none      (sem internet)
    ├── /forensics_raw/     (imagem original, read-only)
    ├── /forensics_ewf/     (mount ewf para E01 → ewf1)
    └── /forensics/partN/   (partições NTFS montadas)
```

---

## Formatos suportados

| Formato | Extensão | Ferramenta |
|---------|----------|------------|
| EnCase (single) | `.E01` | ewfmount |
| EnCase (multi-part) | `.E01 .E02 ...` | ewfmount (automático) |
| RAW / DD | `.dd .raw .img` | mount directo |
| Virtual Hard Disk | `.vhd` | qemu-nbd |
| VMware | `.vmdk` | qemu-nbd |

---

## Instalação

### Pré-requisitos
- [Docker Desktop](https://www.docker.com/products/docker-desktop) (actualizado)
- [Ollama](https://ollama.com/download) com `ollama pull qwen2.5:7b`
- [uv](https://docs.astral.sh/uv/) (gestor de pacotes Python recomendado)

### 1. Construir a imagem Docker

```bash
docker build -t forensics-sandbox ./docker
```

> Na primeira execução demora alguns minutos (instala ferramentas forenses).

### 2. Instalar dependências Python

Com `uv` (recomendado):
```bash
uv sync
```

Com `pip`:
```bash
pip install -r agent/requirements.txt
```

### 3. Colocar a imagem forense
```
evidence/
└── imagem.E01   ← coloca aqui (ou .dd, .vhd, .vmdk)
```

### 4. Configurar o modelo (opcional)

Criar ficheiro `.env` na raiz (ou em `agent/`):
```
OLLAMA_MODEL=qwen2.5:7b
OLLAMA_URL=http://localhost:11434
MAX_ITERATIONS=15
```

---

## Utilização

Com `uv` (recomendado):
```bash
uv run agent/main.py
```

Com Python directamente:
```bash
python agent/main.py
```

### Exemplos de perguntas ao agente

```
Tu: Quais são os utilizadores existentes?
Tu: Quantos utilizadores existem?
Tu: Lista os ficheiros do desktop de Jimmy Wilson
Tu: Encontra todos os ficheiros PDF
Tu: Qual é o MD5 do ficheiro R40599.pdf?
Tu: Qual é o esquema de partições do disco?
***Tu: Mostra os event logs do sistema***
Tu: Mostra os metadados EXIF de uma fotografia
Tu: Que chaves de registo estão configuradas para auto-arranque?
Tu: Mostra os ficheiros modificados entre 25 e 27 de maio de 2015
Tu: Que versão do Windows está instalada?

Tu: Quando foi instalado o sistema operativo.
Tu: Quando foi usado pela última vez.
Tu: Quais os programas instalados no sistema operativo.
Tu: Que sistema operativo é este?

browser history
Tu: Identify websites visited by a suspect
Tu: Find file downloads and their source URLs
Tu: Extract search queries entered in search engines
Tu: Determine timeline of web activity
Tu: Find saved credentials or form data (X) ### tem que ser trabalhada , key3.db/key4.db e de ferramentas específicas como o firefox_decrypt.

Jump Lists
Tu: Identify recently accessed documents, images, and files
Tu: Find evidence that specific files were opened by a user
Tu: Determine which applications were used most frequently
Tu: Recover file paths even if the files were later deleted
Tu: Build a timeline of user activity

string_search
Tu: Find all email addres in jimmy wilsons files
Tu: search for the word "password" in all documents
Tu: find all URLs in jimmy wilsons documents
Tu: search for ip address across all user files
Tu: extract all strings from a suspicious executable on the desktop

Prefecth
Tu: Prove that CMD.exe was executed on the system
Tu: When was the last time a program ran?
Tu: Find evidence of suspicious tools or malware that were run
Tu: What programs were executed most recently
Tu: Was BCTextEncoder.exe ever executed
```

### Comandos especiais
- `estrutura` — mostra o que está montado em /forensics
- `limpar` — limpa o histórico de conversa
- `sair` — termina o programa

---

## Sistema de Skills

O agente usa um sistema de **skills modulares** para injetar conhecimento forense específico no contexto, apenas quando relevante para a pergunta do utilizador. Isto poupa contexto e foca o modelo na ferramenta certa.

As skills estão em `skills/*.txt` e são carregadas automaticamente no arranque. Para cada pergunta, o sistema seleciona a skill mais relevante por keyword matching e injeta os exemplos de uso no system prompt.

| Skill | Ferramenta | Casos de uso |
|-------|-----------|--------------|
| `exiftool` | ExifTool | Metadados EXIF de imagens e documentos |
| `reglookup` | reglookup | Consulta directa a hives do registo Windows |
| `regripper` | RegRipper | Análise forense automatizada do registo |
| `timestamps` | find / stat | Timestamps de ficheiros, intervalos de datas, timelines |

Para adicionar uma nova skill, basta criar um ficheiro `skills/nome.txt` seguindo o formato de `skills/TEMPLATE.txt`. Nenhuma alteração de código é necessária.

---

## Estrutura do projecto

```
aiagent-forensics/
├── agent/
│   ├── main.py          ← agente principal (chatbot ReAct)
│   ├── skills.py        ← carregamento e selecção de skills
│   ├── tools.py         ← execução de comandos no container
│   └── requirements.txt
├── docker/
│   ├── Dockerfile       ← imagem Docker com ferramentas forenses
│   └── entrypoint.sh    ← auto-detecção e montagem da imagem
├── skills/
│   ├── TEMPLATE.txt     ← template para novas skills
│   ├── exiftool.txt
│   ├── reglookup.txt
│   ├── regripper.txt
│   └── timestamps.txt
├── evidence/            ← coloca aqui a imagem forense (não commitar)
└── exports/             ← ficheiros de output gerados pelo agente
```

---

## Notas técnicas

- O `entrypoint.sh` detecta automaticamente o tipo de imagem, monta o E01 via `ewfmount`, identifica as partições com `mmls` e monta cada partição NTFS via `losetup` + kernel NTFS driver
- O agente implementa um loop ReAct manual: invoca o LLM, extrai tool calls (nativo ou fallback JSON), executa no container, injeta o resultado como `ToolMessage` e repete até o modelo responder sem tool calls
- Inclui detecção de loops: se o modelo repetir o mesmo comando consecutivamente, é injectado um nudge para forçar uma abordagem diferente
- O `docker exec` usa `bash -c` para preservar espaços em paths (ex: `Jimmy Wilson`)
- Output acima de 100 linhas é guardado em `/tmp/` dentro do container; o modelo recebe as primeiras 100 linhas e instruções para usar `grep`/`head`

---

## Orientadores
- Miguel Negrão — miguel.negrao@ipleiria.pt
- Miguel Frade — miguel.frade@ipleiria.pt
- Patrício Domingues — patricio.domingues@ipleiria.pt
