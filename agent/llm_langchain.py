import os

from langchain_ollama import ChatOllama                  #importa uma classe que permite comunicar com um modelo local do ollama atraves do langchain
from langchain_core.prompts import ChatPromptTemplate    #importa a classe usada ara construir prompts com mensagens do tipo system e human

from tools.commands import list_dir, mmls_partitions, fls_list

from agent.json_utils import extract_json_from_llm
from agent.validation import validate_decision_structure

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

E01_DEFAULT = os.path.join(_PROJECT_ROOT, "evidence", "2020JimmyWilson.E01")
EVIDENCE_DIR_DEFAULT = os.path.join(_PROJECT_ROOT, "evidence")
OFFSET_DEFAULT = "65664"

# Variáveis de ambiente para configurar o modelo Ollama (opcional, com valores padrão)
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1")


ALLOWED_TOOLS = {
    "list_dir",
    "mmls_partitions",
    "fls_list"
}


def build_llm():
    # cria instância do modelo (evita repetir código em várias funções)
    return ChatOllama(
        model=OLLAMA_MODEL,
        base_url=OLLAMA_BASE_URL,
        temperature=0,  # respostas determinísticas
    )


def decide_tool(query: str) -> dict:
    """recebe query, que é uma string com a pergunta do utilizador
    devolve um dict, ou seja, um dicionário Python
    {"tool": "...", "args": {...}}."""
    
    llm = build_llm()

    # Prompt com duas partes: "system" (instruções fixas) e "human" (pergunta do utilizador)
    prompt = ChatPromptTemplate.from_messages([
        ("system",
         "És um assistente forense dentro de um container Linux.\n"
         "Tens acesso a estas tools:\n"
         "1) list_dir(path)\n"
         "2) mmls_partitions(e01_path)\n"
         "3) fls_list(e01_path, offset)\n\n"
         "Responde APENAS com JSON válido no formato:\n"  # força JSON para facilitar o parsing
         '{{"tool":"list_dir|mmls_partitions|fls_list","args":{{}}}}'
         "Regras:\n"
         "- Se o utilizador pedir o que existe na pasta de evidências, usa list_dir.\n"
         "- Se pedir partições, usa mmls_partitions.\n"
         "- Se pedir listar ficheiros da partição ou raiz, usa fls_list.\n"
         f"- Se não indicar offset, usa {OFFSET_DEFAULT}.\n"
         f"- Se não indicar e01_path, usa {E01_DEFAULT}."),
        ("human", "{input}")
    ])

    #aplica o prompt e depois envia o resultado para o llm
    #passa-lhe os dados reais (query)
    chain = prompt | llm
    response = chain.invoke({"input": query})

    # o content vem como uma string: '{"tool":"list_dir","args":{"path":"/evidence"}}'
    # o extract_json_from_llm converte num dicionário Python: {"tool": "list_dir", "args": {"path": "/evidence"}}
    content = response.content if hasattr(response, "content") else str(response)
    decision = extract_json_from_llm(content)
    validate_decision_structure(decision)
    return decision


def execute_tool(decision: dict):
    """Executa a tool decidida pelo LLM."""
    
    tool = decision.get("tool")
    args = decision.get("args", {})

    if tool not in ALLOWED_TOOLS:
        raise ValueError(f"Tool não permitida: {tool}")

    # Argumentos com fallback para os valores padrão
    e01_path = args.get("e01_path", E01_DEFAULT)
    offset = args.get("offset", OFFSET_DEFAULT)
    path = args.get("path", EVIDENCE_DIR_DEFAULT)

    if tool == "list_dir":
        return list_dir(path)

    elif tool == "mmls_partitions":
        return mmls_partitions(e01_path)

    elif tool == "fls_list":
        return fls_list(e01_path, offset)


def answer_from_tool_result(query: str, decision: dict, tool_result: str):
    """Usa novamente o LLM para interpretar o output da tool e gerar uma resposta mais clara."""

    llm = build_llm()

    prompt = ChatPromptTemplate.from_messages([
        ("system",
         "És um assistente forense.\n"
         "Recebeste a pergunta do utilizador, a tool usada e o output dessa tool.\n"
         "Explica o resultado de forma clara e técnica.\n"
         "Não inventes informação.\n"
         "Baseia-te apenas no output fornecido.\n"),
        ("human",
         "Pergunta do utilizador:\n"
         "{query}\n\n"
         "Tool utilizada:\n"
         "{decision}\n\n"
         "Output da tool:\n"
         "{tool_result}")
    ])

    chain = prompt | llm

    response = chain.invoke({
        "query": query,
        "decision": str(decision),
        "tool_result": tool_result
    })

    return response.content if hasattr(response, "content") else str(response)


def main():
    """Loop interativo: lê perguntas, decide ferramenta via LLM e executa-a."""
    
    while True:
        query = input("Pergunta (ou 'sair'): ").strip()

        if query.lower() in ("sair", "exit", "quit"):
            break

        try:
            decision = decide_tool(query)

            print("\n--- Decisão ---")
            print(decision)

            # executa a tool escolhida
            result = execute_tool(decision)

            print("\n--- Resultado ---")
            print(result)

            # usa o LLM novamente para interpretar o resultado
            print("\nA interpretar resultado...")
            final_answer = answer_from_tool_result(query, decision, result)

            print("\n--- Resposta final ---")
            print(final_answer)
            print()

        except Exception as e:
            print(f"Erro: {e}")  # ex: JSON inválido na resposta do LLM


if __name__ == "__main__":
    main()