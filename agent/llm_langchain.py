import json
import os

from langchain_ollama import ChatOllama                  #importa uma classe que permite comunicar com um modelo local do ollama atraves do langchain
from langchain_core.prompts import ChatPromptTemplate    #importa a classe usada ara construir prompts com mensagens do tipo system e human

from tools.commands import list_dir, mmls_partitions, fls_list

E01_DEFAULT = "/evidence/2020JimmyWilson.E01"   
OFFSET_DEFAULT = "65664"                        

# Variáveis de ambiente para configurar o modelo Ollama (opcional, com valores padrão)
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1")


def decide_tool(query: str) -> dict:
    """recebe query, que é uma string com a pergunta do utilizador
    devolve um dict, ou seja, um dicionário Python
    {"tool": "...", "args": {...}}."""
    # temperature=0: respostas determinísticas (sem aleatoriedade)
    llm = ChatOllama(
        model=OLLAMA_MODEL,
        base_url=OLLAMA_BASE_URL,
        temperature=0,  
    )

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
         "- Se o utilizador pedir o que existe em /evidence, usa list_dir.\n"
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

    content = response.content if hasattr(response, "content") else str(response)
    return json.loads(content)  # converte resposta JSON em dicionário Python

    #o content vem como uma string: '{"tool":"list_dir","args":{"path":"/evidence"}}'
    #o json.loads converte num dicionário Python: {"tool": "list_dir", "args": {"path": "/evidence"}}

def main():
    """Loop interativo: lê perguntas, decide ferramenta via LLM e executa-a."""
    while True:
        query = input("Pergunta (ou 'sair'): ").strip()
        if query.lower() in ("sair", "exit", "quit"):
            break

        try:
            decision = decide_tool(query)
            tool = decision.get("tool")
            args = decision.get("args", {})

            # Argumentos com fallback para os valores padrão
            e01_path = args.get("e01_path", E01_DEFAULT)
            offset = args.get("offset", OFFSET_DEFAULT)
            path = args.get("path", "/evidence")

            if tool == "list_dir":
                result = list_dir(path)
            elif tool == "mmls_partitions":
                result = mmls_partitions(e01_path)
            elif tool == "fls_list":
                result = fls_list(e01_path, offset)
            else:
                result = f"Tool inválida: {tool}"

            print("\n--- Decisão ---")
            print(decision)
            print("\n--- Resultado ---")
            print(result)
            print()

        except Exception as e:
            print(f"Erro: {e}")  # ex: JSON inválido na resposta do LLM


if __name__ == "__main__":
    main()