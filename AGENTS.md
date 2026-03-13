# AIAgentForensics Instructions

## Architecture
- Keep LangChain orchestration with ChatOllama backend in `agent/llm_langchain.py`.
- Use local MCP layer (`mcp_local/server.py`, `mcp_local/client.py`) for tool-like orchestration functions.
- Keep CLI interaction style (`main()` input loop) simple and stable.
- For non-visual disk-image questions, use MCP forensic query path (`query_evidence`) to gather read-only artifacts from `.E01`.

## Intent Policy
- Allowed intents only:
  - `general_description`
  - `object_presence`
  - `object_location`
  - `forensic_trace_detection`
  - `scene_relationships`
  - `insufficient_visual_evidence`
  - `unsafe_inference`
- Classifier output must include:
  - `intent`
  - `rewritten_question`
  - `constraints`
  - `template_name`
  - `needs_image`
- Inventory-style questions (e.g. "what exists in /evidence") must map to `general_description` with `needs_image=false`.

## Template Policy
- Always fetch prompt template via MCP (`get_prompt_template`).
- If template is missing/invalid, fallback to a safe generic visual-analysis template.
- Final responses must be grounded in visible evidence only.
- For non-visual inventory responses, ground answers only on MCP case context.
- For artifact-level answers (users, partitions, file paths/sizes), ground answers on MCP forensic query output.
