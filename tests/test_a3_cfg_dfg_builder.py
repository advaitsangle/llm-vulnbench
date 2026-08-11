"""Real-parser sanity checks for `a3_cfg_dfg_context.build_cfg_dfg`.

Skipped (not failed) when the `structural` extra isn't installed
"""

from __future__ import annotations

import pytest

tree_sitter = pytest.importorskip("tree_sitter")

from vulnbench.conditions import ast_support  # noqa: E402
from vulnbench.conditions.a3_cfg_dfg_context import build_cfg_dfg  # noqa: E402

JAVA_SNIPPET = """
class Foo {
    void bar(String id) {
        String q = "x";
        if (id != null) {
            q = "y";
        } else {
            q = "z";
        }
        for (int i = 0; i < 10; i++) {
            q = q + i;
        }
    }
}
"""


def _build(code: str = JAVA_SNIPPET, max_chars: int = 100_000):
    tree = ast_support.parse_tree("Foo.java", code)
    return build_cfg_dfg(tree, max_chars)


def test_finds_the_function_scope_and_its_line_range():
    text, truncated = _build()
    assert not truncated
    assert "FUNCTION bar (L3-L13)" in text


def test_if_else_produces_true_false_branch_edges():
    text, _ = _build()
    assert "[true]" in text
    assert "[false]" in text


def test_loop_produces_loop_and_back_edges():
    text, _ = _build()
    assert "[loop]" in text
    assert "[back]" in text


def test_dfg_reports_parameter_def_and_reassignment_defs():
    text, _ = _build()
    # `id` is a parameter (defined at the signature); `q` is reassigned in both
    # branches and inside the loop, so it should carry more than one def line.
    assert "id: def=L3" in text
    lines = {ln.strip() for ln in text.splitlines()}
    q_line = next(ln for ln in lines if ln.startswith("q: "))
    assert q_line.count("L") >= 3  # at least the declaration + two reassignments


def test_no_function_scope_falls_back_to_a_module_scope():
    text, truncated = _build("int TOP_LEVEL = 1;\n")
    assert not truncated
    assert "FUNCTION bar" not in text  # no method in this snippet
    # Still produces *something* structural for the implicit whole-file scope,
    # rather than an empty string.
    assert "MODULE" in text
    assert "TOP_LEVEL" in text


def test_block_label_keeps_a_wrapped_statement_whole():
    # Benchmark is google-java-formatted, so sink calls wrap. Keeping only the first
    # physical line dropped the argument — `println(` with nothing in it.
    code = (
        "class Foo {\n"
        "    void bar(String u) {\n"
        "        response.getWriter().println(\n"
        '                "prefix" + u + "suffix");\n'
        "    }\n"
        "}\n"
    )
    tree = ast_support.parse_tree("Foo.java", code)
    text, _ = build_cfg_dfg(tree, 100_000)

    block = next(ln for ln in text.splitlines() if "[STMT" in ln)
    assert "prefix" in block and "suffix" in block and "u" in block
    assert block == block.strip() or "\n" not in block  # still one line


def test_comments_are_not_basic_blocks():
    # line_comment/block_comment are *named* nodes, so they used to become blocks
    # and the edge chain threaded through them.
    code = (
        "class Foo {\n"
        "    void bar(String u) {\n"
        "        // put stuff in the collection\n"
        "        int a = 1;\n"
        "        /* another */\n"
        "        sink(u);\n"
        "    }\n"
        "}\n"
    )
    tree = ast_support.parse_tree("Foo.java", code)
    text, _ = build_cfg_dfg(tree, 100_000)

    assert "put stuff" not in text and "another" not in text
    blocks = [ln for ln in text.splitlines() if "[STMT" in ln]
    assert len(blocks) == 2
    assert text.count("->") == 1  # a straight edge, not one hop per comment


def test_finally_body_becomes_blocks_reachable_from_every_path():
    # A sink in a cleanup block used to appear in no block and on no edge at all.
    code = (
        "class Foo {\n"
        "    void bar(String u) {\n"
        "        try { risky(u); }\n"
        "        catch (Exception e) { log(e); }\n"
        '        finally { Runtime.getRuntime().exec("cleanup " + u); }\n'
        "    }\n"
        "}\n"
    )
    tree = ast_support.parse_tree("Foo.java", code)
    text, _ = build_cfg_dfg(tree, 100_000)

    assert "cleanup" in text
    # finally runs on the normal path and out of the handler, so both reach it.
    assert text.count("[finally]") == 2
    assert "[catch]" in text


def test_block_label_caps_a_long_statement_with_an_ellipsis():
    from vulnbench.conditions.a3_cfg_dfg_context import _MAX_BLOCK_CHARS

    long_arg = "A" * (_MAX_BLOCK_CHARS + 60)
    tree = ast_support.parse_tree(
        "Foo.java", f'class Foo {{ void bar() {{ sink("{long_arg}"); }} }}\n'
    )
    text, _ = build_cfg_dfg(tree, 100_000)

    block = next(ln for ln in text.splitlines() if "[STMT" in ln)
    assert block.endswith("…")
    assert long_arg not in block


def test_truncates_and_reports_it():
    text, truncated = _build(max_chars=20)
    assert truncated
    assert len(text) == 20
