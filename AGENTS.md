# AIAgentForensics Instructions

## Architecture
- Keep LangChain orchestration with ChatOllama backend in `agent/llm_langchain.py`.
- Use local MCP layer (`mcp_local/server.py`, `mcp_local/client.py`) for tool orchestration.
- Keep CLI interaction style (`main()` input loop) simple and stable.
- Preserve split routing:
  - `visual` domain: image-grounded reasoning only.
  - `artifact` domain: MCP tool execution first, then grounded response.
- Preserve literal path handling:
  - Literal filesystem queries (for example `/evidence`, `./x`, `../x`) must use direct filesystem tools.
  - Do not mix host filesystem listing with forensic-image expansion unless intent requires it.
- Preserve conversation-aware reference resolution:
  - Track and use `last_path`, `last_artifact`, `last_artifact_type`, `last_user`.
  - Underspecified follow-ups should resolve to the most recent valid forensic artifact when appropriate.

## Intent Policy
- Supported visual intents:
  - `general_description`
  - `object_presence`
  - `object_location`
  - `forensic_trace_detection`
  - `scene_relationships`
- Supported artifact intents:
  - `directory_listing`
  - `path_lookup`
  - `file_search`
  - `timeline_lookup`
  - `artifact_lookup`
  - `image_partition_inspection`
  - `partition_root_listing`
  - `user_enumeration`
  - `insufficient_evidence`
  - `unsafe_inference`
- Classifier output must include:
  - `domain`
  - `intent`
  - `rewritten_question`
  - `entities`
  - `constraints`
  - `tool_plan`
  - `needs_image`
- Entity fields expected in orchestration:
  - `user`
  - `application`
  - `target_path`
  - `action`
  - `path_scope`
  - `artifact_type`
  - `timestamp_target`
  - `operation`
  - `reference_source`
- Classification guardrails:
  - User-profile folder queries (for example Desktop of a user) must route to forensic user-profile navigation, not host `list_directory`.
  - Partition table questions map to `image_partition_inspection`.
  - Primary partition root entry questions map to `partition_root_listing`.
  - User inventory questions (for example "which users exist") map to `user_enumeration`.

## Template Policy
- Always fetch prompt template via MCP (`get_prompt_template`).
- If template is missing/invalid, fallback to a safe generic visual-analysis template.
- Visual responses must be grounded in visible evidence only.
- Artifact responses must be grounded in MCP tool outputs.
- For deterministic listing intents (`directory_listing`, `partition_root_listing`, `user_enumeration`), prefer direct tool-derived outputs over free-form LLM narration.

## MCP Tool Policy
- Keep and use dedicated artifact tools:
  - `stat_path`, `list_directory`
  - `inspect_image_partitions`
  - `list_primary_partition_root`
  - `list_users`
  - `resolve_user_profile`, `get_special_folder`, `list_user_directory`
  - `query_evidence` (fallback for broader artifact lookups)
- Routing requirements:
  - `image_partition_inspection` -> `inspect_image_partitions` only.
  - `partition_root_listing` -> `list_primary_partition_root` only.
  - `user_enumeration` -> `list_users` only.
  - User Desktop/Documents/Downloads listing -> `resolve_user_profile`, `get_special_folder`, `list_user_directory`.
  - Literal host path listing -> `list_directory`/`stat_path` only.
