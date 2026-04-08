"""
skills.py — Sistema de skills forenses modulares
Carrega, seleciona e injeta skills relevantes no contexto do agente.
"""

import os
import re
import unicodedata
from dataclasses import dataclass, field


# ─── Modelo de uma skill ──────────────────────────────────────────────────────

@dataclass
class Skill:
    name: str
    description: str
    keywords: list[str]
    content: str          # Corpo completo após o separador ---
    filepath: str

    def __repr__(self):
        return f"Skill({self.name!r}, keywords={len(self.keywords)})"


# ─── Parser de ficheiros .txt ─────────────────────────────────────────────────

def _parse_skill_file(filepath: str) -> Skill | None:
    """Lê um ficheiro de skill e extrai metadata + conteúdo."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return None

    # Separa header (metadata) do body (conteúdo)
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


# ─── Carregamento de todas as skills ──────────────────────────────────────────

def load_skills(skills_dir: str | None = None) -> list[Skill]:
    """Carrega todos os ficheiros .txt da directoria de skills."""
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


# ─── Seleção de skills relevantes ─────────────────────────────────────────────

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
    # Portuguese stop words (common in user queries)
    "o", "os", "as", "um", "uma", "uns", "umas",
    "de", "do", "da", "dos", "das", "em", "no", "na", "nos", "nas",
    "por", "para", "com", "sem", "que", "se", "eu", "tu", "ele", "ela",
    "nos", "vos", "eles", "elas", "este", "esta", "esse", "essa",
    "quero", "preciso", "como", "qual", "quais", "onde",
    "e", "ou", "mas", "nao", "sim", "mais", "muito",
})

def _normalize(text: str) -> str:
    """Remove acentos para comparação independente de diacríticos."""
    return unicodedata.normalize("NFD", text).encode("ascii", "ignore").decode("ascii")


def _tokenize(text: str) -> set[str]:
    """Tokeniza texto em palavras normalizadas, removendo stop words e acentos."""
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
    Seleciona as skills mais relevantes para uma query do utilizador.

    Usa keyword matching com scoring baseado em:
    1. Match exato de tokens da query com keywords da skill
    2. Match de substring (keyword contida no query ou vice-versa)

    Retorna no máximo `max_skills` skills, ordenadas por relevância.
    """
    query_tokens = _tokenize(query)
    query_lower = query.lower()

    if not query_tokens:
        return []

    scored: list[tuple[float, Skill]] = []

    for skill in skills:
        score = 0.0

        # 1. Match exato de tokens com keywords
        for kw in skill.keywords:
            kw_tokens = set(kw.split())
            # Keyword multi-palavra: todas as palavras presentes na query
            if kw_tokens and kw_tokens.issubset(query_tokens):
                score += 2.0
            # Keyword como substring da query
            elif kw in query_lower:
                score += 1.5

        # 2. Match de tokens individuais
        for token in query_tokens:
            for kw in skill.keywords:
                if token == kw:
                    score += 1.0
                elif token in kw or kw in token:
                    score += 0.5

        # 3. Match no nome e descrição da skill
        skill_name_tokens = _tokenize(skill.name)
        skill_desc_tokens = _tokenize(skill.description)
        name_overlap = len(query_tokens & skill_name_tokens)
        desc_overlap = len(query_tokens & skill_desc_tokens)
        score += name_overlap * 1.5
        score += desc_overlap * 0.5

        # Normalizar pelo número de keywords para não favorecer skills com muitas keywords
        normalizer = max(len(skill.keywords), 1)
        normalized_score = score / normalizer

        if normalized_score >= min_score:
            scored.append((normalized_score, skill))

    # Ordenar por score decrescente
    scored.sort(key=lambda x: x[0], reverse=True)

    return [skill for _, skill in scored[:max_skills]]


# ─── Formatação para injeção no prompt ─────────────────────────────────────────

def _extract_examples(content: str, max_commands: int = 2) -> str:
    """Extrai apenas linhas de comando dos blocos de código (sem comentários)."""
    lines = content.splitlines()
    commands: list[str] = []
    in_block = False
    for line in lines:
        if line.strip().startswith("```"):
            in_block = not in_block
            continue
        if in_block:
            stripped = line.strip()
            # Ignorar comentários e linhas vazias
            if stripped and not stripped.startswith("#"):
                commands.append(stripped)
                if len(commands) >= max_commands:
                    break
    return " ; ".join(commands)


def format_skills_context(skills: list[Skill]) -> str:
    """Formata as skills para serem injetadas no system prompt.

    Injeta o conteúdo completo de cada skill selecionada (tabelas, avisos, exemplos).
    """
    if not skills:
        return ""

    parts = []
    for skill in skills:
        parts.append(f"### SKILL: {skill.name}\n{skill.content}")
    return "\n\n".join(parts)
