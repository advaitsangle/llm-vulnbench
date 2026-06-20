"""Detection metrics shared by every scorer.

precision, recall, F1, and false-positive rate — the OWASP-Benchmark metric set —
computed from one confusion count so the Benchmark scorer and the realistic-app
webapp scorer report identically.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Metrics:
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def fpr(self) -> float:
        """False-positive rate = FP / (FP + TN). The Benchmark's noise axis."""
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    @property
    def youden_j(self) -> float:
        """recall - fpr. The OWASP Benchmark 'score' is exactly this."""
        return self.recall - self.fpr

    def to_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "fpr": round(self.fpr, 4),
            "youden_j": round(self.youden_j, 4),
        }


def confusion_to_metrics(tp: int, fp: int, fn: int, tn: int) -> Metrics:
    return Metrics(tp=tp, fp=fp, fn=fn, tn=tn)
