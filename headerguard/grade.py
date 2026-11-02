from __future__ import annotations

from .model import FAIL, Check

GRADES = ("A+", "A", "B", "C", "D", "F")
THRESHOLDS = ((95, "A+"), (90, "A"), (80, "B"), (70, "C"), (60, "D"))
DEALBREAKERS = {"https", "tls"}  # plain HTTP or a broken certificate caps the grade at F


def score(checks: list[Check]) -> int:
    return max(0, 100 - sum(c.penalty for c in checks))


def grade(checks: list[Check]) -> str:
    if any(c.id in DEALBREAKERS and c.status == FAIL for c in checks):
        return "F"
    points = score(checks)
    for threshold, letter in THRESHOLDS:
        if points >= threshold and (letter != "A+" or not any(c.status == FAIL for c in checks)):
            return letter
    return "F"


def at_least(letter: str, minimum: str) -> bool:
    return GRADES.index(letter) <= GRADES.index(minimum)
