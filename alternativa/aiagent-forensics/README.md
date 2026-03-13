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
├── forensics_image/  ← coloca aqui a imagem forense
└── Container Docker (sandbox isolada)
    ├── --network none      (sem internet)
    ├── --privileged        (para montagens)
    ├── /forensics_raw/     (imagem original, read-only)
    ├── /forensics_ewf/     (mount ewf para E01)
    └── /forensics/partN/   (partições acessíveis)
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

### 1. Pré-requisitos
- [Docker Desktop](https://www.docker.com/products/docker-desktop)
- [Ollama](https://ollama.com/download) com `ollama pull llama3`
- Python 3.11+

### 2. Construir a imagem Docker
```bash
# No VSCode: Ctrl+Shift+P → Tasks: Run Task → 🐳 Build Docker Image
# Ou no terminal:
docker build -t forensics-sandbox ./docker
```

### 3. Instalar dependências Python
```bash
# No VSCode: Ctrl+Shift+P → Tasks: Run Task → 📦 Install Python Dependencies
# Ou:
pip install -r agent/requirements.txt
```

### 4. Configurar o `.env`
Edita `agent/.env` e ajusta o caminho para a tua imagem forense:
```
FORENSICS_IMAGE_PATH=C:\forensics-agent\forensics_image
OLLAMA_MODEL=llama3
```

### 5. Colocar a imagem forense
```
forensics_image/
└── imagem.E01   ← coloca aqui (ou .dd, .vhd, etc.)
```

---

## Utilização

```bash
# No VSCode: F5  (usa launch.json)
# Ou:
cd agent && python main.py
```

### Exemplos de perguntas ao agente

```
Tu: Quantos utilizadores existem neste sistema?
Tu: Encontra todos os ficheiros PDF modificados em Fevereiro de 2014
Tu: Qual é o MD5 do ficheiro pdf.pdf?
Tu: Há algum email suspeito nos documentos do utilizador?
Tu: Procura por flags no formato CTF{...}
Tu: Qual é o esquema de partições do disco?
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
│   ├── main.py          ← agente principal (chatbot)
│   ├── tools.py         ← execução de comandos no container
│   ├── requirements.txt
│   └── .env             ← configuração (não commitar)
├── docker/
│   ├── Dockerfile       ← imagem Docker com ferramentas forenses
│   └── entrypoint.sh    ← auto-detecção e montagem da imagem
├── forensics_image/     ← coloca aqui a imagem forense (não commitar)
├── .vscode/
│   ├── launch.json      ← F5 para correr
│   └── tasks.json       ← tarefas rápidas (build, test, stop)
└── README.md
```

---

## Orientadores
- Miguel Negrão — miguel.negrao@ipleiria.pt
- Miguel Frade — miguel.frade@ipleiria.pt
- Patrício Domingues — patricio.domingues@ipleiria.pt
