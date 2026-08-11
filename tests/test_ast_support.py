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


def test_render_ast_carries_leaf_source_text():
    # Node types alone name no code: a sink and a safe helper both render as
    # method_invocation over identifier. Without the leaf text there is nothing in
    # the prompt for the model to find a vulnerability *in*.
    code = (
        "class Foo {\n"
        '    void bar(String id) { st.executeQuery("SELECT * FROM u WHERE i=" + id); }\n'
        "}\n"
    )
    tree = ast_support.parse_tree("Foo.java", code)
    text, _ = ast_support.render_ast(tree, max_chars=100_000)

    assert "identifier [L2]  executeQuery" in text
    assert "identifier [L2]  id" in text
    assert "SELECT * FROM u WHERE i=" in text
    # Interior nodes stay bare — node.text there is the whole subtree, which would
    # re-emit the file once per level of nesting.
    assert "class_declaration [L1]" in text
    assert "class Foo" not in text


def test_render_ast_caps_a_long_leaf():
    literal = "A" * (ast_support._MAX_LEAF_CHARS + 50)
    tree = ast_support.parse_tree("Foo.java", f'class Foo {{ String s = "{literal}"; }}\n')
    text, _ = ast_support.render_ast(tree, max_chars=100_000)

    assert literal not in text
    assert "A" * ast_support._MAX_LEAF_CHARS + "…" in text


def test_render_ast_flattens_multiline_leaves_to_one_line():
    # One node per line is the whole format; a leaf spanning newlines must not break it.
    tree = ast_support.parse_tree("Foo.py", 'x = """alpha\nbeta"""\n')
    text, _ = ast_support.render_ast(tree, max_chars=100_000)

    assert "alpha beta" in text
    assert len(text.splitlines()) == len([ln for ln in text.splitlines() if ln.strip()])


def test_render_ast_truncates_and_reports_it():
    code = "class Foo { void bar() { int x = 1; } }\n"
    tree = ast_support.parse_tree("Foo.java", code)
    text, truncated = ast_support.render_ast(tree, max_chars=10)
    assert truncated
    assert len(text) == 10
