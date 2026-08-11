"""Lazy tree-sitter setup shared by A2 (AST context) and A3 (CFG/DFG context).

Behind the optional ``structural`` extra (``tree-sitter`` + one grammar package per
supported language), so ``import vulnbench`` stays dependency-free
Every function here is safe to call with the extra missing:
:func:`parse_tree` returns ``None`` instead of raising, so a caller can
degrade to raw source for that one file rather than erroring the whole run.
"""

from __future__ import annotations

import os
from typing import Any

_EXT_LANGUAGE = {
    ".java": "java",
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".php": "php",
    ".rb": "ruby",
    ".go": "go",
}

#: One parser per language, built on first use and reused after (parser construction
#: loads a compiled grammar, worth caching
# Keyed by language name, not extension, since e.g. no two extensions
#: currently share one.
_parser_cache: dict[str, Any] = {}


def language_for(path: str) -> str | None:
    """The tree-sitter grammar name for ``path``'s extension, or ``None`` if unmapped."""
    return _EXT_LANGUAGE.get(os.path.splitext(path)[1].lower())


def _build_parser(lang_name: str) -> Any | None:
    """Construct a ``Parser`` for ``lang_name``, importing its grammar package lazily.

    Returns ``None`` (not an exception) when ``tree_sitter`` or the specific
    grammar package isn't installed
    """
    try:
        from tree_sitter import Language, Parser
    except ImportError:
        return None
    try:
        if lang_name == "java":
            import tree_sitter_java as g

            ts_lang = g.language()
        elif lang_name == "python":
            import tree_sitter_python as g

            ts_lang = g.language()
        elif lang_name == "javascript":
            import tree_sitter_javascript as g

            ts_lang = g.language()
        elif lang_name == "typescript":
            import tree_sitter_typescript as g

            ts_lang = g.language_typescript()
        elif lang_name == "php":
            import tree_sitter_php as g

            ts_lang = g.language_php()
        elif lang_name == "ruby":
            import tree_sitter_ruby as g

            ts_lang = g.language()
        elif lang_name == "go":
            import tree_sitter_go as g

            ts_lang = g.language()
        else:
            return None
    except ImportError:
        return None
    return Parser(Language(ts_lang))


def _parser_for(lang_name: str) -> Any | None:
    if lang_name not in _parser_cache:
        _parser_cache[lang_name] = _build_parser(lang_name)
    return _parser_cache[lang_name]


def parse_tree(path: str, code: str) -> Any | None:
    """Parse ``code`` (the contents of ``path``) into a tree-sitter ``Tree``, or ``None``.

    ``None`` covers every reason a file can't be structurally analyzed: an
    unmapped extension, a missing grammar package (the ``structural`` extra
    isn't installed), or ``tree_sitter`` itself missing.
    """
    lang_name = language_for(path)
    if lang_name is None:
        return None
    parser = _parser_for(lang_name)
    if parser is None:
        return None
    return parser.parse(code.encode("utf-8", errors="replace"))


def render_ast(tree: Any, max_chars: int) -> tuple[str, bool]:
    """Render a parsed tree as compact indented text: ``type [Lline]`` per named node.

    Only *named* nodes (tree-sitter's term for grammar productions — identifiers,
    statements, expressions — as opposed to bare punctuation/keyword tokens like
    ``(`` or ``if``) are printed. Indentation follows the real tree depth,
    so a printed node's ancestry (which statement it's nested inside) stays legible
    even where unnamed wrapper nodes are skipped. Returns ``(text, truncated)`` so
    callers can record truncation the same way :func:`source_files.read_capped` does.
    """
    lines: list[str] = []

    def walk(node: Any, depth: int) -> None:
        if node.is_named:
            lines.append(f"{'  ' * depth}{node.type} [L{node.start_point[0] + 1}]")
        for child in node.children:
            walk(child, depth + 1)

    walk(tree.root_node, 0)
    text = "\n".join(lines)
    if len(text) > max_chars:
        return text[:max_chars], True
    return text, False
