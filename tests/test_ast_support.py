"""Real-parser sanity checks for `ast_support`.
"""

from __future__ import annotations

import pytest

tree_sitter = pytest.importorskip("tree_sitter")

from vulnbench.conditions import ast_support  # noqa: E402


def test_language_for_known_and_unknown_extensions():
    assert ast_support.language_for("Foo.java") == "java"
    assert ast_support.language_for("foo.py") == "python"
    assert ast_support.language_for("foo.exe") is None


def test_parse_tree_returns_none_for_unmapped_extension():
    assert ast_support.parse_tree("foo.exe", "whatever") is None


def test_parse_tree_and_render_ast_on_a_real_java_snippet():
    code = (
        "class Foo {\n"
        "    void bar(String id) {\n"
        "        if (id != null) {\n"
        "            System.out.println(id);\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    tree = ast_support.parse_tree("Foo.java", code)
    assert tree is not None

    text, truncated = ast_support.render_ast(tree, max_chars=100_000)
    assert not truncated
    assert "class_declaration [L1]" in text
    assert "method_declaration [L2]" in text
    assert "if_statement [L3]" in text
    assert "\n{ [" not in text and not text.startswith("{ [")


def test_render_ast_truncates_and_reports_it():
    code = "class Foo { void bar() { int x = 1; } }\n"
    tree = ast_support.parse_tree("Foo.java", code)
    text, truncated = ast_support.render_ast(tree, max_chars=10)
    assert truncated
    assert len(text) == 10
