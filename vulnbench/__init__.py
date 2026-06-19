"""vulnbench: a benchmark harness for LLM-augmented web vulnerability detection.

The harness runs a ladder of *conditions* (Semgrep, ZAP, LLM, and combinations)
against a *target* application, normalizes every result to a shared
:class:`~vulnbench.schema.Finding`, and scores it against ground truth with one
metrics path. See ``code/claude.md`` for the research design behind this layout.
"""

__version__ = "0.1.0"
