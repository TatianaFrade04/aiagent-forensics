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
    ├── --privileged        (para montagens)
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
- [Ollama](https://ollama.com/download) com `ollama pull llama3.1:8b`
- Python 3.11+

### 1. Construir a imagem Docker

**Linux / macOS (bash):**
```bash
bash build.sh
```

**Windows (PowerShell):**
```powershell
.\build.ps1
```

**Ou directamente:**
```bash
docker build -t forensics-sandbox ./docker
```

> Na primeira execução demora alguns minutos (instala ferramentas forenses).

### 2. Instalar dependências Python
```bash
pip install -r agent/requirements.txt
```

### 3. Colocar a imagem forense
```
evidence/
└── imagem.E01   ← coloca aqui (ou .dd, .vhd, .vmdk)
```

O caminho é detectado automaticamente — não é necessário configurar `.env`.

---

## Utilização

```bash
python agent/main.py
```

### Exemplos de perguntas ao agente

```
Tu: Quais são os utilizadores existentes?
Tu: Quantos utilizadores existem?
Tu: Lista os ficheiros do desktop de Jimmy Wilson
Tu: Encontra todos os ficheiros PDF
Tu: Qual é o MD5 do ficheiro report.pdf?
Tu: Qual é o esquema de partições do disco?
Tu: Mostra os event logs do sistema
```

### Comandos especiais
- `estrutura` — mostra o que está montado em /forensics
- `limpar` — limpa o histórico de conversa
- `sair` — termina o programa

---

## Estrutura do projecto

```
aiagent-forensics/
├── agent/
│   ├── main.py          ← agente principal (chatbot ReAct)
│   ├── tools.py         ← execução de comandos no container
│   └── requirements.txt
├── docker/
│   ├── Dockerfile       ← imagem Docker com ferramentas forenses
│   └── entrypoint.sh    ← auto-detecção e montagem da imagem
├── evidence/            ← coloca aqui a imagem forense (não commitar)
├── exports/             ← ficheiros exportados pelo agente (não commitar)
├── build.sh             ← script de build (Linux/macOS)
├── build.ps1            ← script de build (Windows PowerShell)
├── start_container.ps1  ← inicia o container manualmente (para testes)
├── bash_in_container.ps1← abre bash interativo no container (para testes)
└── .vscode/
    ├── launch.json      ← F5 para correr
    └── tasks.json       ← tarefas rápidas (build, stop)
```

---

## Notas técnicas

- O `entrypoint.sh` detecta automaticamente o tipo de imagem, monta o E01 via `ewfmount`, identifica as partições com `mmls` e monta cada partição NTFS via `losetup` + kernel NTFS driver
- O `docker exec` usa `bash -c` para preservar espaços em paths (ex: `Jimmy Wilson`)
- O agente tem um fallback que detecta tool calls em formato JSON ou Python-like gerados pelo modelo e executa-as automaticamente
- Loop devices são limpos com `losetup -D` a cada arranque para evitar conflitos com execuções anteriores

---

## Orientadores
- Miguel Negrão — miguel.negrao@ipleiria.pt
- Miguel Frade — miguel.frade@ipleiria.pt
- Patrício Domingues — patricio.domingues@ipleiria.pt

