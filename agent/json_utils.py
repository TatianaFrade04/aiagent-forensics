import json
import re



def extract_json_from_llm(text: str) -> dict:
    """
    Extrai JSON da resposta do modelo mesmo que haja texto extra.
    """
    # remover blocos ```json ```
    text = text.replace("```json", "").replace("```", "")
    # encontrar primeiro bloco JSON
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError("Nenhum JSON encontrado na resposta do LLM")
    json_text = match.group(0)
    return json.loads(json_text)