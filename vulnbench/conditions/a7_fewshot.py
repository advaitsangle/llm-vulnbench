"""A7 — Few-shot labeled examples. The model is shown worked cases before the file.

Prompt-level augmentation: B3 asks a cold model for a verdict; A7 first replays a
handful of solved cases as real conversational turns (a ``user`` turn holding a file,
an ``assistant`` turn holding the contract-shaped reply), so the model has a pattern
to imitate. Everything else — system prompt, output contract, per-file loop, scoring —
is B3's, so any difference in the scorecard is attributable to the examples alone.

Deliberately has no chain-of-thought knob: A8 is its own condition, and the two are
never configured together. See :mod:`a8_cot` for why that separation matters — the
example replies here are plain ``{"findings": [...]}`` objects, and pairing them with
a prompt that demands step-by-step reasoning would demonstrate ignoring that demand.

The examples are balanced (vulnerable, safe, vulnerable, safe, vulnerable) so that a
prefix of them does not prime the model toward always finding something.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..corpus import Target
from ..models import Usage
from ..schema import Finding, Location, benchmark_case_of
from .base import Condition, ConditionContext, ConditionResult, Knob
from .llm_common import OUTPUT_CONTRACT, SYSTEM_PROMPT, parse_findings
from .source_files import (
    SAMPLE_KNOBS,
    SCAN_KNOBS,
    iter_source_files,
    read_capped,
    sampled_paths_for,
)


# Built-in few-shot examples
@dataclass(frozen=True)
class _Example:
    path: str   # shown to the model exactly as a file path
    code: str   # the snippet
    reply: str  # the expected JSON response (already contract-shaped)


# Example 1: CWE-89 SQL injection (vulnerable)
_EX1 = _Example(
    path="examples/UserDao.java",
    code="""\
public User findByUsername(HttpServletRequest req) throws SQLException {
    String username = req.getParameter("username");
    String sql = "SELECT * FROM users WHERE username = '" + username + "'";
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery(sql);
    return rs.next() ? mapRow(rs) : null;
}""",
    reply=json.dumps({
        "findings": [{
            "cwe": 89,
            "vuln_type": "SQL Injection",
            "diagnostic": (
                "Untrusted HTTP parameter 'username' is concatenated directly "
                "into a SQL string and executed via Statement.executeQuery."
            ),
            "file": "examples/UserDao.java",
            "line": 3,
            "url": None,
            "param": "username",
            "verdict": "confirmed",
            "confidence": 0.97,
            "evidence": (
                "req.getParameter(\"username\") flows into the SQL string literal "
                "without escaping or parameterisation."
            ),
            "counter_evidence": None,
            "remediation": (
                "Replace with PreparedStatement and setString(1, username) "
                "instead of string concatenation."
            ),
            "requires_human_review": False,
        }]
    }),
)

# Example 2: prepared statement — safe (no finding)
_EX2 = _Example(
    path="examples/ProductDao.java",
    code="""\
public Product findById(HttpServletRequest req) throws SQLException {
    int id = Integer.parseInt(req.getParameter("id"));
    PreparedStatement ps = conn.prepareStatement(
        "SELECT * FROM products WHERE id = ?");
    ps.setInt(1, id);
    ResultSet rs = ps.executeQuery();
    return rs.next() ? mapRow(rs) : null;
}""",
    reply=json.dumps({"findings": []}),
)

# Example 3: CWE-78 OS Command injection (vulnerable)
_EX3 = _Example(
    path="examples/PingServlet.java",
    code="""\
protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws IOException {
    String host = req.getParameter("host");
    Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
    resp.getWriter().write("done");
}""",
    reply=json.dumps({
        "findings": [{
            "cwe": 78,
            "vuln_type": "OS Command Injection",
            "diagnostic": (
                "Untrusted HTTP parameter 'host' is concatenated into a shell "
                "command string passed to Runtime.exec."
            ),
            "file": "examples/PingServlet.java",
            "line": 4,
            "url": None,
            "param": "host",
            "verdict": "confirmed",
            "confidence": 0.95,
            "evidence": (
                "req.getParameter(\"host\") is appended to \"ping -c 1 \" "
                "and executed as a system command with no validation."
            ),
            "counter_evidence": None,
            "remediation": (
                "Use a hostname whitelist, or pass arguments as String[] to exec() "
                "to avoid shell interpretation."
            ),
            "requires_human_review": False,
        }]
    }),
)

# Example 4: path checked against canonical whitelist — safe
_EX4 = _Example(
    path="examples/FileServlet.java",
    code="""\
private static final String BASE = "/var/www/static/";

protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws IOException {
    String name = req.getParameter("file");
    File f = new File(BASE, name).getCanonicalFile();
    if (!f.getPath().startsWith(BASE)) {
        resp.sendError(403);
        return;
    }
    Files.copy(f.toPath(), resp.getOutputStream());
}""",
    reply=json.dumps({"findings": []}),
)

# Example 5: CWE-79 reflected XSS (vulnerable)
_EX5 = _Example(
    path="examples/SearchServlet.java",
    code="""\
protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws IOException {
    String query = req.getParameter("q");
    PrintWriter out = resp.getWriter();
    resp.setContentType("text/html");
    out.println("<h1>Results for: " + query + "</h1>");
}""",
    reply=json.dumps({
        "findings": [{
            "cwe": 79,
            "vuln_type": "Cross-site Scripting (XSS)",
            "diagnostic": (
                "Untrusted HTTP parameter 'q' is written directly into HTML "
                "output without escaping."
            ),
            "file": "examples/SearchServlet.java",
            "line": 6,
            "url": None,
            "param": "q",
            "verdict": "confirmed",
            "confidence": 0.96,
            "evidence": (
                "req.getParameter(\"q\") is concatenated into an HTML string "
                "and sent to the client with no HTML-encoding."
            ),
            "counter_evidence": None,
            "remediation": "HTML-encode before writing: ESAPI.encoder().encodeForHTML(query).",
            "requires_human_review": False,
        }]
    }),
)

EXAMPLES: tuple[_Example, ...] = (_EX1, _EX2, _EX3, _EX4, _EX5)


class A7FewShot(Condition):
    id = "A7"
    label = "Few-shot labeled examples"
    needs_model = True
    needs_source = True
    knobs = SCAN_KNOBS + SAMPLE_KNOBS + (
        Knob("shots", "int", 4,
             help=f"how many built-in labeled examples to show (1-{len(EXAMPLES)})"),
    )

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        assert ctx.model is not None
        max_files = int(self.cfg(ctx, "max_files")) or None
        max_bytes = int(self.cfg(ctx, "max_file_bytes"))
        # Floor of 1: A7 with zero examples is B3, and a condition that can be
        # configured into being another one reports under the wrong name.
        shots = max(1, min(int(self.cfg(ctx, "shots")), len(EXAMPLES)))

        # --sample overrides max_files: the smoke slice *is* the file set.
        paths = sampled_paths_for(self, ctx, target.source_path)
        if paths is None:
            paths = iter_source_files(target.source_path, max_files)

        findings: list[Finding] = []
        usage = Usage()
        scanned = 0
        truncated: list[str] = []
        scored_cases: set[str] = set()

        for path in paths:
            tc = benchmark_case_of(path)
            if tc is not None:
                scored_cases.add(tc)  # in scope even if the model finds nothing in it
            code, was_truncated = read_capped(path, max_bytes)
            if not code:
                continue
            if was_truncated:
                truncated.append(path)

            completion = ctx.model.complete(self._messages(path, code, shots))
            usage = usage + completion.usage
            for f in parse_findings(completion.text, self.id):
                # Pin the location to the file we actually scanned.
                if f.location.file is None:
                    f.location = Location.source(file=path, line=f.location.line)
                findings.append(f)
            scanned += 1

        trace: dict[str, Any] = {
            "files_scanned": scanned,
            "model": ctx.model.name,
            "truncated_files": len(truncated),
            "max_file_bytes": max_bytes,
            "shots": shots,  # post-clamp, so the record says what was actually shown
        }
        return ConditionResult(
            findings=findings,
            usage=usage,
            trace=trace,
            scored_cases=scored_cases or None,
        )

    def _messages(self, path: str, code: str, shots: int) -> list[dict]:
        messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]
        for ex in EXAMPLES[:shots]:
            messages.append({"role": "user", "content": _user_prompt(ex.path, ex.code)})
            messages.append({"role": "assistant", "content": ex.reply})
        messages.append({"role": "user", "content": _user_prompt(path, code)})
        return messages


def _user_prompt(path: str, code: str) -> str:
    return (
        f"Analyze this source file for security vulnerabilities.\n\n"
        f"File: {path}\n```\n{code}\n```\n\n{OUTPUT_CONTRACT}"
    )
