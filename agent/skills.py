"""
skills.py — Modular forensic skills system
Loads, selects, and injects relevant skills into the agent context.
"""

import os
import re
import unicodedata
from dataclasses import dataclass, field


# ─── Skill model ─────────────────────────────────────────────────────────────

@dataclass
class Skill:
    name: str
    description: str
    keywords: list[str]
    content: str          # Full body after the --- separator
    filepath: str

    def __repr__(self):
        return f"Skill({self.name!r}, keywords={len(self.keywords)})"


# ─── Skill file parser ───────────────────────────────────────────────────────

def _parse_skill_file(filepath: str) -> Skill | None:
    """Read a skill .txt file and extract metadata + body content."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return None

    # Split header (metadata) from body (content)
    parts = text.split("\n---\n", maxsplit=1)
    header = parts[0]
    body = parts[1].strip() if len(parts) > 1 else ""

    name = ""
    description = ""
    keywords: list[str] = []

    for line in header.splitlines():
        line = line.strip()
        if line.upper().startswith("SKILL:"):
            name = line.split(":", 1)[1].strip()
        elif line.upper().startswith("DESCRIPTION:"):
            description = line.split(":", 1)[1].strip()
        elif line.upper().startswith("KEYWORDS:"):
            raw = line.split(":", 1)[1]
            keywords = [k.strip().lower() for k in raw.split(",") if k.strip()]

    if not name:
        name = os.path.splitext(os.path.basename(filepath))[0]

    return Skill(
        name=name,
        description=description,
        keywords=keywords,
        content=body,
        filepath=filepath,
    )


# ─── Load all skills ─────────────────────────────────────────────────────────

def load_skills(skills_dir: str | None = None) -> list[Skill]:
    """Load all .txt skill files from the skills directory."""
    if skills_dir is None:
        skills_dir = os.path.join(os.path.dirname(__file__), "..", "skills")
    skills_dir = os.path.abspath(skills_dir)

    if not os.path.isdir(skills_dir):
        return []

    skills: list[Skill] = []
    for filename in sorted(os.listdir(skills_dir)):
        if not filename.endswith(".txt") or filename.upper() == "TEMPLATE.TXT":
            continue
        filepath = os.path.join(skills_dir, filename)
        skill = _parse_skill_file(filepath)
        if skill:
            skills.append(skill)

    return skills


# ─── Relevant skill selection ────────────────────────────────────────────────

_STOP_WORDS = frozenset({
    "a", "an", "the", "is", "are", "was", "were", "be", "been",
    "do", "does", "did", "have", "has", "had", "will", "would",
    "can", "could", "should", "may", "might", "shall",
    "i", "me", "my", "you", "your", "we", "our", "they", "them",
    "it", "its", "he", "she", "him", "her", "his",
    "this", "that", "these", "those", "what", "which", "who",
    "in", "on", "at", "to", "for", "of", "with", "from", "by",
    "and", "or", "but", "not", "no", "if", "then", "so",
    "all", "any", "some", "how", "when", "where", "why",
    "there", "here", "about", "up", "out", "very",
})

def _normalize(text: str) -> str:
    """Strip accents for diacritic-independent comparison."""
    return unicodedata.normalize("NFD", text).encode("ascii", "ignore").decode("ascii")


def _tokenize(text: str) -> set[str]:
    """Tokenize text into normalised words, removing stop words and accents."""
    normalized = _normalize(text.lower())
    words = re.findall(r"[a-zA-Z0-9_./\-]+", normalized)
    return {w for w in words if w not in _STOP_WORDS and len(w) > 1}


def select_skills(
    query: str,
    skills: list[Skill],
    max_skills: int = 1,
    min_score: float = 0.10,
) -> list[Skill]:
    """
    Select the most relevant skills for a user query.

    Uses keyword matching with multi-tier scoring:
    1. Exact token match between query tokens and skill keywords
    2. Substring match (keyword contained in query or vice-versa)

    Returns at most `max_skills` skills, sorted by relevance score.
    """
    query_tokens = _tokenize(query)
    query_lower = _normalize(query.lower())

    if not query_tokens:
        return []

    scored: list[tuple[float, Skill]] = []

    for skill in skills:
        score = 0.0

        # 1. Exact token match with keywords
        for kw in skill.keywords:
            kw_tokens = set(kw.split())
            # Multi-word keyword: all words must be present in the query
            if kw_tokens and kw_tokens.issubset(query_tokens):
                score += 2.0
            # Keyword as substring of the (translated) query
            elif kw in query_lower:
                score += 1.5

        # 2. Individual token match
        for token in query_tokens:
            for kw in skill.keywords:
                if token == kw:
                    score += 1.0
                elif token in kw or kw in token:
                    score += 0.5

        # 3. Match against skill name and description tokens
        skill_name_tokens = _tokenize(skill.name)
        skill_desc_tokens = _tokenize(skill.description)
        name_overlap = len(query_tokens & skill_name_tokens)
        desc_overlap = len(query_tokens & skill_desc_tokens)
        score += name_overlap * 1.5
        score += desc_overlap * 0.5

        # Normalise by keyword count to avoid bias toward high-keyword skills
        normalizer = max(len(skill.keywords), 1)
        normalized_score = score / normalizer

        if normalized_score >= min_score:
            scored.append((normalized_score, skill))

    # Sort by score descending
    scored.sort(key=lambda x: x[0], reverse=True)

    return [skill for _, skill in scored[:max_skills]]


# ─── Formatting for prompt injection ─────────────────────────────────────────

def _extract_examples(content: str, max_commands: int = 2) -> str:
    """Extract only command lines from code blocks (skip comments and blank lines)."""
    lines = content.splitlines()
    commands: list[str] = []
    in_block = False
    for line in lines:
        if line.strip().startswith("```"):
            in_block = not in_block
            continue
        if in_block:
            stripped = line.strip()
            # Skip comments and blank lines
            if stripped and not stripped.startswith("#"):
                commands.append(stripped)
                if len(commands) >= max_commands:
                    break
    return " ; ".join(commands)


def format_skills_context(skills: list[Skill], evidence: str = "{evidence}") -> str:
    """Format selected skills for injection into the system prompt.

    Injects the full content of each selected skill (tables, warnings, examples).
    Hardcoded {evidence} placeholders in skill files are replaced with the
    actual evidence path before injection.
    """
    if not skills:
        return ""

    parts = []
    for skill in skills:
        content = skill.content.replace("{evidence}", evidence)
        parts.append(f"### SKILL: {skill.name}\n{content}")
    return "\n\n".join(parts)
