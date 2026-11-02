from __future__ import annotations

from dataclasses import dataclass, field

PASS, WARN, FAIL, INFO = "pass", "warn", "fail", "info"


@dataclass
class Snapshot:
    """Everything the checks need from one fetch. Pure data, so checks are trivially testable."""

    requested: str
    url: str
    status: int
    headers: list[tuple[str, str]]
    redirects: list[str] = field(default_factory=list)
    tls: dict | None = None

    @property
    def https(self) -> bool:
        return self.url.lower().startswith("https://")

    def get(self, name: str) -> str | None:
        name = name.lower()
        return next((v for k, v in self.headers if k.lower() == name), None)

    def get_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]


@dataclass
class Check:
    id: str
    title: str
    status: str
    detail: str
    penalty: int = 0
