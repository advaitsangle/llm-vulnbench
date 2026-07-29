"""A7 — Few-shot labeled examples / A8 — Chain-of-thought reasoning.

All findings are returned in the common JSON contract and scored identically to
B3. No changes to llm_common.py or the core harness are needed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..corpus import Target
from ..models import Usage
from ..schema import Finding, Location, benchmark_case_of
from .base import Condition, ConditionContext, ConditionResult, Knob
from .llm_common import OUTPUT_CONTRACT, SYSTEM_PROMPT, _extract_json_object, parse_findings
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


COT_PREFIX = (
    "Before listing findings, emit a top-level \"analysis\" array of 3–6 short "
    "steps. Each step is a plain string. Work through:\n"
    "  1. Entry points — which inputs are untrusted (HTTP params, headers, "
    "cookies, request bodies, env vars)?\n"
    "  2. Sinks — which dangerous operations does this code invoke (SQL, OS "
    "command, file path, HTML output, reflection, deserialization)?\n"
    "  3. Data flows — does any untrusted input reach a sink without "
    "sufficient sanitization or parameterization?\n"
    "  4. Mitigations — are there validators, allow-lists, prepared statements, "
    "or other controls that break the flow?\n"
    "  5. Conclusion — what verdicts follow?\n\n"
    "The full response shape (analysis comes first):\n"
    "{\n"
    "  \"analysis\": [\"<step 1>\", \"<step 2>\", ...],\n"
    "  \"findings\": [ ... ]\n"
    "}\n\n"
    "If you find nothing, return {\"analysis\": [\"No untrusted inputs reach "
    "dangerous sinks.\"], \"findings\": []}.\n\n"
)

COT_SYSTEM_SUFFIX = (
    " Before reporting findings, reason step by step: identify entry points, "
    "trace data flows to sinks, check mitigations, then commit to verdicts."
)


class PromptVariantCondition(Condition):
    needs_model = True
    needs_source = True
    knobs = SCAN_KNOBS + SAMPLE_KNOBS + (
        Knob("fewshot", "bool", False,
             help="prepend labeled worked examples as conversational turns before the file"),
        Knob("cot", "bool", False,
             help="require step-by-step reasoning (analysis array) before any verdict"),
        Knob("shots", "int", 4,
             help="how many built-in labeled examples few-shot shows (max 5)"),
    )

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        assert ctx.model is not None
        max_files = int(self.cfg(ctx, "max_files")) or None
        max_bytes = int(self.cfg(ctx, "max_file_bytes"))

        paths = sampled_paths_for(self, ctx, target.source_path)
        if paths is None:
            paths = iter_source_files(target.source_path, max_files)

        findings: list[Finding] = []
        usage = Usage()
        scanned = 0
        truncated: list[str] = []
        scored_cases: set[str] = set()
        cot_followed = 0

        for path in paths:
            tc = benchmark_case_of(path)
            if tc is not None:
                scored_cases.add(tc)
            code, was_truncated = read_capped(path, max_bytes)
            if not code:
                continue
            if was_truncated:
                truncated.append(path)

            messages = self._messages(path, code, ctx)
            completion = ctx.model.complete(messages)
            usage = usage + completion.usage

            raw_findings, analysis = _parse_cot_reply(completion.text)
            if analysis is not None:
                cot_followed += 1

            for f in raw_findings:
                if f.location.file is None:
                    f.location = Location.source(file=path, line=f.location.line)
                # Attach reasoning to extra so findings.json records it.
                if analysis is not None:
                    f.extra = {**f.extra, "cot_analysis": analysis}
                findings.append(f)
            scanned += 1

        trace: dict[str, Any] = {
            "files_scanned": scanned,
            "model": ctx.model.name,
            "truncated_files": len(truncated),
            "max_file_bytes": max_bytes,
            "fewshot": bool(self.cfg(ctx, "fewshot")),
            "cot": bool(self.cfg(ctx, "cot")),
        }
        if bool(self.cfg(ctx, "cot")):
            trace["cot_followed_count"] = cot_followed
            trace["cot_followed_pct"] = (
                round(cot_followed / scanned, 3) if scanned else 0.0
            )

        return ConditionResult(
            findings=findings,
            usage=usage,
            trace=trace,
            scored_cases=scored_cases or None,
        )

    def _messages(self, path: str, code: str, ctx: ConditionContext) -> list[dict]:
        do_fewshot = bool(self.cfg(ctx, "fewshot"))
        do_cot = bool(self.cfg(ctx, "cot"))
        shots = max(0, min(int(self.cfg(ctx, "shots")), len(EXAMPLES)))

        system = SYSTEM_PROMPT + (COT_SYSTEM_SUFFIX if do_cot else "")
        user_content = (_user_prompt_cot if do_cot else _user_prompt)(path, code)

        messages: list[dict] = [{"role": "system", "content": system}]
        if do_fewshot and shots > 0:
            for ex in EXAMPLES[:shots]:
                ex_user = (_user_prompt_cot if do_cot else _user_prompt)(ex.path, ex.code)
                messages.append({"role": "user", "content": ex_user})
                messages.append({"role": "assistant", "content": ex.reply})
        messages.append({"role": "user", "content": user_content})
        return messages


class A7FewShot(PromptVariantCondition):
    id = "A7"
    label = "Few-shot labeled examples"
    knobs = (Knob("fewshot", "bool", True,
                  help="prepend labeled worked examples as conversational turns before the file"),)


class A8ChainOfThought(PromptVariantCondition):
    id = "A8"
    label = "Chain-of-thought (reason before verdict)"
    knobs = (Knob("cot", "bool", True,
                  help="require step-by-step reasoning (analysis array) before any verdict"),)


def _user_prompt(path: str, code: str) -> str:
    return (
        f"Analyze this source file for security vulnerabilities.\n\n"
        f"File: {path}\n```\n{code}\n```\n\n{OUTPUT_CONTRACT}"
    )


def _user_prompt_cot(path: str, code: str) -> str:
    return (
        f"Analyze this source file for security vulnerabilities.\n\n"
        f"File: {path}\n```\n{code}\n```\n\n{COT_PREFIX}{OUTPUT_CONTRACT}"
    )


# CoT reply parser
def _parse_cot_reply(text: str) -> tuple[list[Finding], list[str] | None]:
    obj = _extract_json_object(text)
    analysis: list[str] | None = None
    if obj is not None:
        raw = obj.get("analysis")
        if isinstance(raw, list) and raw:
            steps = [s for s in raw if isinstance(s, str)]
            if steps:
                analysis = steps
    findings = parse_findings(text, "A7_A8")
    return findings, analysis
