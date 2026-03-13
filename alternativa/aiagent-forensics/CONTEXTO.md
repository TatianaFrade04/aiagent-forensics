# AIAgent@forensics — Contexto do Projecto

## Descrição
Agente LLM com paradigma ReAct para investigação forense digital.
Politécnico de Leiria — ESTG | Licenciatura em Engenharia Informática 2025-2026
Orientadores: Miguel Negrão, Miguel Frade, Patrício Domingues

## Arquitectura
```
Windows (máquina do utilizador)
├── Ollama ou API externa (LLM)
├── Python/LangChain + LangGraph (agente)
├── forensics_image/ (imagem forense aqui)
└── Container Docker (sandbox isolada)
    ├── --privileged, --network none
    ├── /forensics_raw/ (imagem E01, read-only)
    ├── /forensics_ewf/ (ewfmount monta aqui → ewf1)
    └── /forensics/     (partições — vazio, usa fls/icat)
```

## Imagem Forense Actual
- Ficheiro: `2020JimmyWilson.E01`
- Fonte: https://cfreds.nist.gov/all/DFIR_AB/ForensicsImageTestimage
- Formato: EnCase E01, GPT, NTFS
- Partição principal: offset sector **65664**
- Raw device: `/forensics_ewf/ewf1`
- Montagem directa falha no container → usa Sleuth Kit

## Comandos Importantes
```bash
# Listar utilizadores
fls -o 65664 /forensics_ewf/ewf1 4213

# Listar ficheiros recursivamente
fls -r -o 65664 /forensics_ewf/ewf1

# Procurar ficheiro por nome
fls -r -o 65664 /forensics_ewf/ewf1 | grep -i NOME

# Ler ficheiro pelo inode
icat -o 65664 /forensics_ewf/ewf1 INODE

# Calcular MD5
icat -o 65664 /forensics_ewf/ewf1 INODE | md5sum
```

## Inodes Conhecidos
| Inode | Descrição |
|-------|-----------|
| 4213  | Pasta USERS |
| 36    | Jimmy Wilson (home) |
| 57    | Desktop do Jimmy Wilson |
| 76    | Documents do Jimmy Wilson |
| 896   | ID%20Theft.pdf |
| 929   | IDtheftrev.pdf |
| 932   | pdf-0009-taking-charge.pdf |
| 933   | pdf-0014-identity-theft.pdf |
| 934   | pdf-0094-identity-theft-affidavit.pdf |
| 936   | R40599.pdf (MD5: 9804ff1093891320c37c2035080437f4) |
| 77    | zxp8-datasheet-en-us.pdf |
| 4214  | Pasta Windows |

## Utilizadores do Sistema
- BillyBob (inode 4376)
- Fred Flintstone (inode 4374)
- James Russell (inode 4375)
- Jimmy Wilson (inode 36)
- Joe Nameless (inode 4377)

## Desktop do Jimmy Wilson (inode 57)
- BCTextEncoder.exe
- Jose Badguy/ (pasta com imagens e ficheiro codificado)
- Robert Ripoff/ (pasta com imagens e ficheiro codificado)
- OpenOffice 4.0.1 Installation Files/

## Respostas CFReDS Confirmadas
| Q | Pergunta | Resposta |
|---|----------|----------|
| Q5 | Utilizadores do sistema | 5: BillyBob, Fred Flintstone, James Russell, Jimmy Wilson, Joe Nameless |
| Q8 | MD5 do pdf.pdf | FALSE — ficheiro não existe com esse nome |
| Q9 | Esquema de partições | GPT |
| R40599.pdf MD5 | | 9804ff1093891320c37c2035080437f4 |

## Estrutura do Projecto
```
aiagent-forensics/
├── agent/
│   ├── main.py          (agente v1 — LangGraph directo, sem MCP)
│   ├── main_mcp.py      (agente v2 — cliente MCP via stdio)
│   ├── mcp_server.py    (servidor MCP — expõe run_forensics_command)
│   ├── tools.py         (execução de comandos no container Docker)
│   ├── requirements.txt
│   └── .env             (OLLAMA_MODEL, OLLAMA_URL, FORENSICS_IMAGE_PATH)
├── docker/
│   ├── Dockerfile       (Ubuntu 22.04 + ewf-tools + sleuthkit + ntfs-3g)
│   └── entrypoint.sh    (auto-detecta E01/DD/VHD/VMDK e tenta montar)
├── forensics_image/     (coloca aqui a imagem forense)
├── CONTEXTO.md          (este ficheiro)
└── .vscode/
    ├── launch.json      (F5 para correr)
    └── tasks.json       (build docker, install deps, stop container)
```

## Modelos Testados
| Modelo | RAM | Tool Use | Resultado |
|--------|-----|----------|-----------|
| llama3.1 | 4.9GB | ❌ | Imprime JSON sem executar |
| mistral | ~4GB | ❌ | Descreve sem executar |
| llama3.2 | 2GB | ❌ | Inventa formato errado |
| qwen2.5:7b | ~5GB | ⚠️ | Funciona às vezes |
| qwen2.5:14b | ~9GB | ✅ | Melhor resultado (responde em tailandês — corrigir prompt) |

## Problemas Resolvidos
1. **Backslashes no .env** — tools.py lê o .env manualmente para evitar escape sequences
2. **Container sem ewfmount** — corrigido usando `sleep infinity` como CMD (entrypoint corre primeiro)
3. **Montagem directa falha** — normal em containers sem loop devices; usa fls/icat directamente
4. **Modelo não usa ferramenta** — problema dos LLMs locais pequenos; qwen2.5:14b é o melhor local

## Prompt Actual (main.py)
```python
prompt=(
    "Responde SEMPRE em portugues. "
    "IMPORTANTE: Usa SEMPRE a ferramenta run_forensics_command para executar comandos. "
    "NUNCA digas 'vou executar' sem realmente chamar a ferramenta. "
    "Cada vez que precisares de informacao, chama run_forensics_command imediatamente.\n"
    "Es um agente especialista em investigacao forense digital. "
    "REGRAS OBRIGATORIAS:\n"
    "1. NUNCA respondas sem usar a ferramenta run_forensics_command primeiro.\n"
    "2. A pasta /forensics esta VAZIA. Nao tentes caminhos como /forensics/Users.\n"
    "3. Para aceder a ficheiros DEVES usar SEMPRE fls e icat com offset 65664 sobre /forensics_ewf/ewf1.\n"
    "4. FLUXO para encontrar ficheiro:\n"
    "   Passo 1: fls -r -o 65664 /forensics_ewf/ewf1 | grep -i NOME\n"
    "   Passo 2: obtem inode do resultado\n"
    "   Passo 3: icat -o 65664 /forensics_ewf/ewf1 INODE | md5sum\n"
    "5. Para listar utilizadores: fls -o 65664 /forensics_ewf/ewf1 4213\n"
)
```

## Arquitectura MCP (v2)
```
main_mcp.py  (cliente MCP, async)
    │  stdio (subprocesso Python)
    ▼
mcp_server.py  (servidor FastMCP)
    │  docker exec
    ▼
forensics_sandbox  (container Docker)
    └── /forensics_ewf/ewf1  (imagem E01 montada)
```

- `main_mcp.py` usa `MultiServerMCPClient` do `langchain-mcp-adapters`
- O servidor MCP é lançado automaticamente como subprocesso via `sys.executable`
- Comunicação por stdio (JSON-RPC sobre pipes stdin/stdout)
- Quando o agente termina, o servidor MCP encerra e `atexit` para o container

## Dependências Python
```
langchain>=1.2
langchain-ollama>=1.0
langchain-community>=0.4
langchainhub>=0.1
langgraph>=1.1
python-dotenv>=1.2
mcp                      (SDK oficial MCP — servidor FastMCP)
langchain-mcp-adapters   (cliente MCP para LangChain/LangGraph)
```

## Como Mudar para API Externa (Gemini/OpenAI)
Ver secção abaixo.

---

## Migração para API Gemini

### 1. Instalar dependência
```bash
pip install langchain-google-genai
```

### 2. Obter API Key
https://aistudio.google.com/app/apikey (gratuito com limites generosos)

### 3. Adicionar ao .env
```
GEMINI_API_KEY=AIza...
USE_GEMINI=true
```

### 4. Alterar main.py
Substituir o bloco do LLM:
```python
# ANTES (Ollama local)
from langchain_ollama import ChatOllama
llm = ChatOllama(model=OLLAMA_MODEL, base_url=OLLAMA_URL, temperature=0)

# DEPOIS (Gemini API)
from langchain_google_genai import ChatGoogleGenerativeAI
llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash",
    google_api_key=os.getenv("GEMINI_API_KEY"),
    temperature=0,
)
```

### Modelos Gemini recomendados
- `gemini-2.0-flash` — rápido, barato, excelente tool use ✅
- `gemini-1.5-pro` — mais capaz para raciocínio complexo

### Notas
- O tool use funciona muito melhor com APIs comerciais
- O resto do código (tools.py, Docker, entrypoint) não muda nada
- Gemini 2.0 Flash tem tier gratuito generoso (1500 req/dia)
