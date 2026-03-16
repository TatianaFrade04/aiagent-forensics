"""
Semantic parser for the capability-based forensic assistant.

The LLM's ONLY role here is language understanding: map a natural-language
forensic question to one capability name and extract its parameters.
Routing, validation, and tool calls all live in other modules.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field

from agent.capabilities import capability_names, supported_capability_names

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Output schema  (replaces the old OrchestrationDecision entirely)
# ---------------------------------------------------------------------------

class ParsedRequest(BaseModel):
    """
    Minimal parser output produced by the LLM.

    Fields intentionally excluded vs. the old OrchestrationDecision schema:
      - domain          (implicit: all supported capabilities are artifact-domain)
      - intent          (replaced by capability)
      - tool_plan       (computed deterministically in executor.py — NOT by the LLM)
      - needs_image     (not needed; capability registry encodes tool requirements)
      - constraints     (enforced by the validation layer, not the LLM)
      - rewritten_question (not needed; original question is preserved)
    """

    capability: str = Field(
        description=(
            "Name of the matched forensic capability, or 'unsupported_request' "
            "if the question is outside the supported scope."
        )
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Parser confidence: 0.0 = no match, 1.0 = certain.",
    )
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Extracted parameters required by the matched capability.",
    )


# ---------------------------------------------------------------------------
# Parser prompt
# ---------------------------------------------------------------------------

_PARSER_PROMPT_TEMPLATE = """\
You are the semantic parser for a forensic artifact analysis assistant.

Your ONLY job:
1. Map the user forensic question to exactly one capability from the list below.
2. Extract the minimum parameters needed to execute that capability.
3. Return a confidence score 0.0-1.0.

== Supported capabilities ==
{capability_list}

== Parameter extraction rules ==
- image_path   : forensic image file path (e.g. /evidence/disk.E01).
                 Include ONLY if explicitly mentioned by the user.
- user         : a username or person's name mentioned in the question.
- folder       : a folder name -- Desktop, Downloads, Documents, Pictures,
                 Music, AppData, Videos (or a non-English alias of these).
- file_path    : an explicit path containing at least one path separator (/ or \\).
                 Extract the EXACT path as given, WITHOUT surrounding quotes and WITHOUT
                 adding any prefix such as /evidence/.
                 Use ONLY when the user specifies directory components (not a bare name).
                 Examples: 'Users/Jimmy/Desktop/file.eml' -> "Users/Jimmy/Desktop/file.eml",
                           '/evidence/notes.txt' (has /evidence/ prefix) -> "notes.txt".
- filename     : a bare filename with NO path separators, typically quoted by the user.
                 Use this when the user names a file WITHOUT stating its folder location.
                 Extract WITHOUT surrounding quotes and WITHOUT adding any path prefix.
                 Examples: '"notes.txt"' -> "notes.txt",
                           '"The Width Of A Circle.txt"' -> "The Width Of A Circle.txt",
                           'report.pdf' -> "report.pdf".
- algorithm    : hash algorithm -- one of: md5, sha1, sha256.
                 Normalize aliases: "sha-1" -> "sha1", "sha-256" -> "sha256".
- hive         : registry hive -- one of: sam, ntuser, software, system, security.
- key_path     : a specific registry key path if mentioned.
- log_name     : event log -- one of: system, application, security.
- event_ids    : list of integer event IDs if explicitly given.
- timestamp    : a date/datetime string (prefer ISO format YYYY-MM-DD or
                 YYYY-MM-DD HH:MM:SS).
- username     : a username for event-log filtering (distinct from user above).
- path         : a literal filesystem path starting with /, ./, ../, or a
                 Windows drive letter.

== Rules ==
- NEVER invent capabilities outside the supported list.
- If the question has no forensic relevance, return capability="unsupported_request",
  confidence=0.0, parameters={{}}.
- If forensically relevant but genuinely ambiguous, return the best match with
  confidence below 0.70.
- If a required parameter is clearly missing, still return the best capability
  but lower confidence accordingly.
- Do NOT output domain, intent, tool_plan, needs_image, constraints, or any
  other field outside the schema.
- Return ONLY a valid JSON object with keys: capability, confidence, parameters.

== Examples ==
Q: "What partitions does the disk image have?"
-> {{"capability": "list_partitions", "confidence": 0.95, "parameters": {{}}}}

Q: "List the files on Jimmy Wilson's Desktop"
-> {{"capability": "list_user_folder", "confidence": 0.95,
    "parameters": {{"user": "Jimmy Wilson", "folder": "Desktop"}}}}

Q: "What is the MD5 hash of /evidence/notes.txt?"
-> {{"capability": "compute_file_hash", "confidence": 0.97,
    "parameters": {{"file_path": "/evidence/notes.txt", "algorithm": "md5"}}}}

Q: "Who are the users in the image?"
-> {{"capability": "list_users", "confidence": 0.98, "parameters": {{}}}}

Q: "What is in the Downloads folder of user admin?"
-> {{"capability": "list_user_folder", "confidence": 0.95,
    "parameters": {{"user": "admin", "folder": "Downloads"}}}}

Q: "Show me the SAM registry for RID numbers"
-> {{"capability": "inspect_registry", "confidence": 0.93,
    "parameters": {{"hive": "sam"}}}}

Q: "When was the system last booted? Check the System event log."
-> {{"capability": "inspect_event_logs", "confidence": 0.90,
    "parameters": {{"log_name": "system"}}}}

Q: "What is the weather today?"
-> {{"capability": "unsupported_request", "confidence": 0.0, "parameters": {{}}}}

Q: "Quando o pc foi ligado pela primeira vez?"
-> {{"capability": "inspect_timeline", "confidence": 0.93,
    "parameters": {{"query": "first"}}}}

Q: "Quando o pc foi usado pela ultima vez?"
-> {{"capability": "inspect_timeline", "confidence": 0.93,
    "parameters": {{"query": "last"}}}}

Q: "When was the computer first used?"
-> {{"capability": "inspect_timeline", "confidence": 0.94,
    "parameters": {{"query": "first"}}}}

Q: "When was the last time the computer was active?"
-> {{"capability": "inspect_timeline", "confidence": 0.94,
    "parameters": {{"query": "last"}}}}

Q: "Quais dias o computador foi ligado?"
-> {{"capability": "inspect_timeline", "confidence": 0.92, "parameters": {{"query": "all"}}}}

Q: "Which days was the computer active?"
-> {{"capability": "inspect_timeline", "confidence": 0.93, "parameters": {{"query": "all"}}}}

Q: "Qual a conta de email do utilizador?"
-> {{"capability": "inspect_email_accounts", "confidence": 0.91, "parameters": {{"query_type": "accounts"}}}}

Q: "Quando o pc foi ligado pela primeira vez?"
-> {{"capability": "inspect_timeline", "confidence": 0.92, "parameters": {{}}}}

Q: "Quando o pc foi usado pela ultima vez?"
-> {{"capability": "inspect_timeline", "confidence": 0.92, "parameters": {{}}}}

Q: "Which days was the computer active?"
-> {{"capability": "inspect_timeline", "confidence": 0.93, "parameters": {{}}}}

Q: "Qual a conta de email do utilizador?"
-> {{"capability": "inspect_email_accounts", "confidence": 0.91, "parameters": {{"query_type": "accounts"}}}}

Q: "Quantos emails existem na imagem?"
-> {{"capability": "inspect_email_accounts", "confidence": 0.88, "parameters": {{"query_type": "count"}}}}

Q: "How many emails are there?"
-> {{"capability": "inspect_email_accounts", "confidence": 0.88, "parameters": {{"query_type": "count"}}}}

Q: "Quantos emails existem?"
-> {{"capability": "inspect_email_accounts", "confidence": 0.88, "parameters": {{"query_type": "count"}}}}

Q: "Mostra o conteudo do email."
-> {{"capability": "inspect_email_accounts", "confidence": 0.85, "parameters": {{"query_type": "accounts"}}}}

Q: "Mostra o conteudo do email /evidence/emails/msg1.eml"
-> {{"capability": "read_file_content", "confidence": 0.94,
    "parameters": {{"file_path": "/evidence/emails/msg1.eml"}}}}

Q: "Show the content of the email file from above."
-> {{"capability": "read_file_content", "confidence": 0.80, "parameters": {{}}}}

Q: "What is the email account of user Jimmy Wilson?"
-> {{"capability": "inspect_email_accounts", "confidence": 0.94,
    "parameters": {{"user": "Jimmy Wilson"}}}}

Q: "What is the cluster size in bytes within the second partition?"
-> {{"capability": "inspect_filesystem", "confidence": 0.93, "parameters": {{"partition_index": 2}}}}

Q: "What is the cluster size in bytes within the first partition?"
-> {{"capability": "inspect_filesystem", "confidence": 0.93, "parameters": {{"partition_index": 1}}}}

Q: "What is the filesystem type of the primary partition?"
-> {{"capability": "inspect_filesystem", "confidence": 0.92, "parameters": {{"partition_index": 1}}}}

Q: "Qual é o GUID do disco fisico?"
-> {{"capability": "inspect_disk_metadata", "confidence": 0.92, "parameters": {{}}}}

Q: "What is the disk GUID in hex?"
-> {{"capability": "inspect_disk_metadata", "confidence": 0.94, "parameters": {{}}}}

Q: "Is the partition schema GPT or MBR?"
-> {{"capability": "inspect_disk_metadata", "confidence": 0.93, "parameters": {{}}}}

Q: "Qual é o tamanho do ficheiro 'The Widht Of a Circle.txt'?"
-> {{"capability": "get_file_size", "confidence": 0.93,
    "parameters": {{"filename": "The Widht Of a Circle.txt"}}}}

Q: "Qual é o tamanho do ficheiro notes.txt?"
-> {{"capability": "get_file_size", "confidence": 0.92,
    "parameters": {{"filename": "notes.txt"}}}}

Q: "How big is the file report.pdf in the forensic image?"
-> {{"capability": "get_file_size", "confidence": 0.91,
    "parameters": {{"filename": "report.pdf"}}}}

Q: "What is the size of the file at USERS/Jimmy Wilson/Documents/report.pdf?"
-> {{"capability": "get_file_size", "confidence": 0.93,
    "parameters": {{"file_path": "USERS/Jimmy Wilson/Documents/report.pdf"}}}}

Q: "Mostra o conteudo do email Users/Jimmy/Desktop/msg.eml"
-> {{"capability": "read_file_content", "confidence": 0.93,
    "parameters": {{"file_path": "Users/Jimmy/Desktop/msg.eml"}}}}

Q: "Show the contents of /evidence/readme.txt"
-> {{"capability": "read_file_content", "confidence": 0.94,
    "parameters": {{"file_path": "/evidence/readme.txt"}}}}

Q: "What is the last boot time? Check the Windows event log"
-> {{"capability": "inspect_event_logs", "confidence": 0.91,
    "parameters": {{"log_name": "system"}}}}

Q: "What is the system uptime on 2014-02-20?"
-> {{"capability": "inspect_event_logs", "confidence": 0.90,
    "parameters": {{"log_name": "system", "timestamp": "2014-02-20"}}}}

Q: "Show me the NTUSER registry hive for user Jimmy Wilson"
-> {{"capability": "inspect_registry", "confidence": 0.93,
    "parameters": {{"hive": "ntuser", "user": "Jimmy Wilson"}}}}

Q: "List the root of the primary partition"
-> {{"capability": "list_primary_partition_root", "confidence": 0.94, "parameters": {{}}}}

Q: "Quais users existem na imagem?"
-> {{"capability": "list_users", "confidence": 0.95, "parameters": {{}}}}
"""


def _build_parser_prompt() -> str:
    lines = [f"  - {name}" for name in supported_capability_names()]
    return _PARSER_PROMPT_TEMPLATE.format(capability_list="\n".join(lines))


# ---------------------------------------------------------------------------
# Build parser callable
# ---------------------------------------------------------------------------

def build_parser(llm: ChatOllama) -> Callable[[str, Optional[str]], ParsedRequest]:
    """
    Return a stateless callable ``parse_question(question, conversation_context)``.

    The LLM is configured with structured output so we always get a ParsedRequest
    back.  If the returned capability is not in the registry, we fall back to
    unsupported_request so the rest of the pipeline never sees an unknown name.
    """
    parser_llm = llm.with_structured_output(ParsedRequest)
    system_prompt = _build_parser_prompt()
    valid_names = set(capability_names())

    def parse_question(
        question: str,
        conversation_context: Optional[str] = None,
    ) -> ParsedRequest:
        context_block = (
            f"\nConversation context (most recent turns):\n{conversation_context}\n"
            if conversation_context
            else ""
        )
        full_prompt = f"{system_prompt}{context_block}\nUser question:\n{question}"
        try:
            result: ParsedRequest = parser_llm.invoke(full_prompt)
        except Exception as exc:
            logger.warning("Parser LLM call failed: %s", exc)
            return ParsedRequest(capability="unsupported_request", confidence=0.0, parameters={})

        # Safety: reject any capability the LLM invented.
        if result.capability not in valid_names:
            logger.warning(
                "Parser returned unknown capability %r — falling back to unsupported_request.",
                result.capability,
            )
            return ParsedRequest(capability="unsupported_request", confidence=0.0, parameters={})

        return result

    return parse_question
