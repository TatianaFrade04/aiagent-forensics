# AIAgent@forensics

**Politécnico de Leiria — ESTG | Licenciatura em Engenharia Informática**  
Final Project 2025–2026

LLM agent using the **ReAct (Reason + Act)** paradigm for digital forensic investigation.
The agent reasons autonomously, executes forensic commands inside an isolated Docker container, and generates detailed reports with the source of each finding.

---

## Architecture

```
Windows (local machine)
├── Ollama            ← LLM model (local or remote server)
├── Python / LangGraph  ← ReAct agent runs here
├── RAG (ChromaDB)    ← document index
├── evidence/         ← place forensic image here (or extracted directory)
├── exports/          ← reports and output files
└── Docker container (isolated sandbox)
    ├── --network none           (no internet)
    ├── /forensics_raw/          (original image, read-only — normal mode)
    ├── /forensics/              (evidence directory — --no-mount mode)
    ├── /forensics_ewf/          (ewf mount for E01 → ewf1)
    ├── /forensics/partN/        (automatically mounted NTFS partitions)
    └── /exports/                (report and file write location)
```

The agent uses a **sliding-window ReAct loop**: when context reaches 70% capacity, it compresses the history into an intermediate report on disk and resumes the investigation. At 85% it forces a conclusion. If the model finishes with less than 25% of context used and intermediate reports exist, the agent detects premature termination and forces a continuation (max. 3 times).

---

## Supported evidence formats

| Format | Extension | Tool |
|--------|-----------|------|
| EnCase (single) | `.E01` | ewfmount |
| EnCase (multi-part) | `.E01 .E02 ...` | ewfmount (automatic) |
| RAW / DD | `.dd .raw .img` | direct mount |
| Virtual Hard Disk | `.vhd` | qemu-nbd |
| VMware | `.vmdk` | qemu-nbd |
| Pre-extracted directory | `folder/` | `--no-mount` |

---

## Installation

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop) (up-to-date, running)
- [Ollama](https://ollama.com/download) with the desired model: `ollama pull gemma4:e4b`
- [uv](https://docs.astral.sh/uv/) (recommended Python package manager)

### 1. Install Python dependencies

```bash
uv sync
```

### 2. Place the evidence

Forensic image:
```
evidence/
└── image.E01   ← (or .dd, .vhd, .vmdk)
```

Or pre-extracted directory (use with `--no-mount`):
```
evidence/
└── part006/
    └── USERS/
        └── ...
```

> The Docker image (`forensics-sandbox`) is built automatically on first run if it does not exist.

---

## Usage

```bash
uv run forensics
```

### Command-line options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--model` | string | `gemma4:e4b` | Ollama model to use |
| `--url` | string | `http://localhost:11434` | Ollama server URL |
| `--ctx` | int | `32768` | Context window size in tokens |
| `--temp` | float | `0.3` | Model temperature |
| `--dir` | path | `./evidence` | Host directory containing the forensic image |
| `--evidence` | path | auto | Partition inside the container to use (e.g. `/forensics/part002`) |
| `--no-mount` | flag | — | Mounts the evidence directory directly at `/forensics` without attempting to mount an E01/DD image |
| `--allow-network` | flag | — | Enables internet access in the container; the agent automatically installs missing tools via `sudo apt-get install` |
| `--no-clear-rag` | flag | — | Keeps RAG-indexed documents from previous sessions |
| `--think` | flag | enabled | Enables model reasoning mode |
| `--debug` | flag | — | Shows raw AIMessage fields for inspection |

### Examples

```bash
# Standard investigation with E01 image
uv run forensics --model gemma4:e4b --ctx 65536

# Model on a remote server
uv run forensics --url http://192.168.1.100:11434 --model gemma4:e4b

# Pre-extracted evidence directory
uv run forensics --no-mount

# Reuse RAG index from previous session
uv run forensics --no-clear-rag
```

### Special chat commands

| Command | Action |
|---------|--------|
| `/exit` | Exits the program (also `/quit`) |
| `/clear` | Clears the conversation history |
| `/structure` | Shows what is mounted at `/forensics` |
| `/clear_rag` | Clears all RAG-indexed documents |

---

## Example questions for the agent

```
What operating system is this and when was it installed?
How many users exist? (filesystem + SAM registry)
List the files on the desktop of <username>
What programs are installed on the system?
Which USB devices have been connected?
Which registry keys are configured for auto-start?
Show files modified between May 25 and 27, 2015
What is the MD5 hash of suspeito.exe?
Show the EXIF metadata of a photograph
Identify websites visited by the suspect (browser history)
Show recently accessed files (Jump Lists)
Prove that cmd.exe was executed on the system (Prefetch)
Search for the word "password" in all documents
What programs are installed and when were they installed?
Which users are defined in the SAM and what is the last login of each?
When was the system powered on and off? (Event Log)
What is the disk partition layout and cluster size of each partition?
Perform a complete analysis of users, installed programs, recent files, and USB devices
```

---

## Skills System

The agent uses **modular skills** to inject specific forensic knowledge into the system prompt, only when relevant to the question. This saves context and focuses the model on the right tool.

Skills are stored in `skills/*.txt` and loaded automatically at startup. For each question, the system selects the most relevant skill by keyword matching.

| Skill | Tool | Use cases |
|-------|------|-----------|
| `browser_history` | sqlite3 | Browser history (Chrome, Firefox, Edge) |
| `disk_images` | mmls / fsstat / sleuthkit | Physical/virtual disk analysis, partition layout, GUIDs, cluster size |
| `event_log` | python-evtx / evtx | Windows Event Log (.evtx) parsing, Event IDs, uptime calculation |
| `exiftool` | ExifTool | EXIF metadata of images and documents |
| `file_search` | find / grep | File search by name, date, content |
| `installed_software` | reglookup / regripper | Installed programs (registry), portable tools (prefetch) |
| `jump_lists` | python-libjumplist | Recently accessed files per application |
| `prefetch` | strings / peparse | Proof of program execution |
| `rag` | ChromaDB | Query indexed documents |
| `recycle_bin` | python / strings | Files deleted from the Recycle Bin |
| `reglookup` | reglookup | Direct query of Windows registry hives |
| `regripper` | RegRipper | Automated forensic registry analysis |
| `sam_users` | reglookup | SAM users, RIDs, last login, password hints |
| `string_search` | strings / grep | Text search in binary files |
| `timestamps` | find / stat | Timestamps, date ranges, timelines |

To add a new skill, create a `skills/name.txt` file following the format of `skills/TEMPLATE.txt`. No code changes are needed.

---

## RAG System

The agent includes a **RAG (Retrieval-Augmented Generation)** pipeline for indexing and querying documents (manuals, forensic reports, case law).

- Supported formats: **PDF, DOCX, CSV, TXT and MD**
- Documents are indexed with local embeddings (`all-MiniLM-L6-v2`) and stored in `chroma_store/`
- The agent has two RAG tools: `ingest_pdf_document` and `query_rag_documents`
- By default, the index is cleared on startup (use `--no-clear-rag` to persist between sessions)

---

## Reports and output

All reports are saved to `exports/` (also mounted at `/exports/` inside the container):

- **Final report** (`export_<timestamp>.txt`) — generated automatically at the end of each investigation, with a header including response time and the original question
- **Intermediate reports** (`intermediate_<n>_<timestamp>.txt`) — created during context compression, consolidated into the final report
- **Output files** — any file saved by the agent to `/exports/` is available in `exports/` on the host

All findings include their **exact source** (full path, hive + registry key, or database file + table).

---

## Project structure

```
aiagent-forensics/
├── agent/
│   ├── main.py          ← main agent (ReAct loop, context compression, reports)
│   ├── skills.py        ← skill loading and selection
│   ├── tools.py         ← Docker container management and command execution
│   └── requirements.txt
├── docker/
│   ├── Dockerfile       ← image with forensic tools (sleuthkit, ewf, reglookup...)
│   └── entrypoint.sh    ← auto-detection and mounting of E01/DD/VHD/VMDK
├── rag/
│   ├── config.py        ← centralised configuration (model, chunking, ChromaDB)
│   ├── indexer.py       ← document ingestion and chunking
│   ├── retriever.py     ← semantic search in ChromaDB
│   └── generator.py     ← response generation with RAG context
├── skills/
│   ├── TEMPLATE.txt     ← template for new skills
│   ├── browser_history.txt
│   ├── disk_images.txt
│   ├── event_log.txt
│   ├── exiftool.txt
│   ├── file_search.txt
│   ├── installed_software.txt
│   ├── jump_lists.txt
│   ├── prefetch.txt
│   ├── rag.txt
│   ├── recycle_bin.txt
│   ├── reglookup.txt
│   ├── regripper.txt
│   ├── sam_users.txt
│   ├── string_search.txt
│   └── timestamps.txt
├── evidence/            ← place forensic image or directory here (do not commit)
├── exports/             ← reports generated by the agent
├── chroma_store/        ← persistent RAG index (do not commit)
└── pyproject.toml
```

---

## Technical notes

- `entrypoint.sh` automatically detects the image type, mounts E01 via `ewfmount`, identifies partitions with `mmls`, and mounts each NTFS partition via `losetup` + the kernel NTFS driver
- With `--no-mount`, the evidence directory is mounted directly at `/forensics`; the entrypoint finds no image and sleeps
- The Docker image `forensics-sandbox` is built automatically if it does not exist (`docker build -t forensics-sandbox ./docker`)
- Output exceeding 100 lines is saved to `/tmp/` inside the container; the agent receives the first 100 lines and instructions to use `grep`/`head`
- Context compression: at 70% capacity, the history is compressed into an intermediate report on disk; at 85% the agent is forced to conclude
- Premature termination detection: if the agent finishes with < 25% of context used and intermediate reports exist, a continuation is forced (max. 3 times)
- Windows user listing always cross-references two sources: the `USERS/` directory (filesystem) and the `/SAM/Domains/Account/Users/Names` key (SAM registry)

---

## Supervisors

- Miguel Negrão — miguel.negrao@ipleiria.pt
- Miguel Frade — miguel.frade@ipleiria.pt
- Patrício Domingues — patricio.domingues@ipleiria.pt
