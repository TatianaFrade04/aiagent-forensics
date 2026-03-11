def validate_decision_structure(decision: dict) -> None:
    if "tool" not in decision:
        raise ValueError("Resposta do LLM não contém 'tool'")
    if "args" not in decision:
        raise ValueError("Resposta do LLM não contém 'args'")
    if not isinstance(decision["args"], dict):
        raise ValueError("'args' deve ser um dicionário")