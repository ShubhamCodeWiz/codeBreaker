"""Result models for code-breaker probes."""

from typing import Literal

from pydantic import BaseModel


class Evidence(BaseModel):
    """One HTTP request made while running a probe."""

    method: str
    path: str
    status_code: int
    note: str | None = None


class ProbeResult(BaseModel):
    """Outcome of a probe.

    PASS means the target resisted the attack (secure for this probe).
    FAIL means the vulnerability was found.
    INCONCLUSIVE means the probe could not run properly, e.g. the control
    request failed, so no verdict is possible.
    """

    probe: str
    endpoint: str
    status: Literal["PASS", "FAIL", "INCONCLUSIVE"]
    summary: str
    evidence: list[Evidence]