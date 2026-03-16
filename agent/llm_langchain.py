import json
import logging
import os
from typing import List, Optional

from langchain_ollama import ChatOllama

from mcp_local import LocalMCPClient, create_default_server
from agent.container import ContainerError, get_manager
from agent.executor import CapabilityState, execute_capability
from agent.normalizer import ValidationError, normalize_parameters, validate_parsed_request
from agent.parser import ParsedRequest, build_parser
from agent.responder import compose_answer
from agent.legacy import (
    ConversationState,
    _build_classifier,
    run_forensic_visual_flow,
    print_plan,
    shorten_text,
    _history_to_text,
)

log = logging.getLogger("forensics.orchestrator")


# =========================
# Config
# =========================

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_EVIDENCE_DIR = os.path.join(_PROJECT_ROOT, "evidence")

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL") or "http://localhost:11434"
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL") or "llama3.1"


# =========================
# Docker
# =========================

def ensure_container() -> None:
    """Best-effort container startup at application launch.

    The real safety-net is in ``ContainerManager.ensure_running()`` which is
    called before every ``docker exec`` inside ``tools/runner.py``.
    """
    try:
        mgr = get_manager()
        mgr.ensure_running()
        log.info("Container '%s' is ready.", mgr.container_name)
    except ContainerError as exc:
        log.warning("Container not available at startup: %s", exc)
        print(f"[docker] Warning: {exc}")
        print("[docker] Will retry automatically when a capability needs the container.")


# =========================
# Pipeline
# =========================

def build_pipeline():
    if not OLLAMA_MODEL:
        raise ValueError("OLLAMA_MODEL is empty.")

    print(f"[ollama] base_url={OLLAMA_BASE_URL}")
    print(f"[ollama] model={OLLAMA_MODEL}")

    llm = ChatOllama(
        model=OLLAMA_MODEL,
        base_url=OLLAMA_BASE_URL,
        temperature=0,
        validate_model_on_init=False,
    )

    classify_question = _build_classifier(llm)
    mcp_server = create_default_server(
        evidence_dir=_EVIDENCE_DIR,
        classify_question=classify_question,
    )
    mcp_client = LocalMCPClient(mcp_server)
    parse_question = build_parser(llm)

    return llm, mcp_client, parse_question


# =========================
# Query flow
# =========================

def run_forensic_query_flow(
    llm: ChatOllama,
    mcp_client: LocalMCPClient,
    parse_question,
    question: str,
    history: List[str],
    cap_state: CapabilityState,
    legacy_state: Optional[ConversationState] = None,
) -> tuple:
    """
    Main query dispatcher.

    1. Parse the question with the semantic parser (LLM, language-only).
    2. Normalize and validate parameters (deterministic Python).
    3. Execute the capability (deterministic MCP tool calls).
    4. Compose the answer grounded in tool outputs.

    Falls back to the legacy visual flow when the capability system cannot
    handle the request (visual questions, low-confidence artifact queries).
    """
    context = _history_to_text(history)
    parsed = parse_question(question, conversation_context=context)
    parsed.parameters = normalize_parameters(parsed.capability, parsed.parameters)

    try:
        params = validate_parsed_request(
            parsed.capability,
            parsed.confidence,
            parsed.parameters,
            evidence_dir=_EVIDENCE_DIR,
            last_known_image_path=cap_state.last_image_path,
            last_known_file_path=cap_state.last_file_path,
        )
    except ValidationError:
        decision, answer = run_forensic_visual_flow(
            llm, mcp_client, question, history, legacy_state
        )
        return decision, answer

    tool_results = execute_capability(mcp_client, parsed.capability, params, cap_state)
    answer = compose_answer(llm, parsed.capability, params, tool_results, original_question=question)
    return parsed, answer


# =========================
# Terminal output
# =========================

def print_final_answer(text: str):
    text = (text or "").strip()
    if text:
        print("\n[resposta final]")
        print(text)


def print_parsed_request(parsed: ParsedRequest) -> None:
    print("\n[parsed request]")
    print(json.dumps(parsed.model_dump(), indent=2, ensure_ascii=False))


# =========================
# Main
# =========================

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    ensure_container()
    llm, mcp_client, parse_question = build_pipeline()
    history: List[str] = []
    cap_state = CapabilityState()
    legacy_state = ConversationState()

    while True:
        query = input("\nPergunta (ou 'sair'): ").strip()

        if query.lower() in ("sair", "exit", "quit"):
            break

        try:
            result, answer = run_forensic_query_flow(
                llm=llm,
                mcp_client=mcp_client,
                parse_question=parse_question,
                question=query,
                history=history,
                cap_state=cap_state,
                legacy_state=legacy_state,
            )

            if isinstance(result, ParsedRequest):
                print_parsed_request(result)
            elif result is not None:
                print_plan(result)

            print_final_answer(answer)

            history.append(f"user: {query}")
            history.append(f"assistant: {shorten_text(answer, max_len=500)}")

            print()

        except Exception as e:
            print(f"\n[erro] {e}")


if __name__ == "__main__":
    main()