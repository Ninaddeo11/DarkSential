"""YAML rule DSL: declarative conditions over behavior features -> ATT&CK techniques.

Rules are data: conditions are a small typed tree (all/any/not/compare)
interpreted here. Nothing from the YAML is ever evaluated as code. Feature
and technique references are validated at load.
"""

from __future__ import annotations

import operator
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.behavior.features import FEATURES, Vector

Op = Literal[">", ">=", "<", "<=", "==", "!="]
_OPS: dict[str, Callable[[float, float], bool]] = {
    ">": operator.gt,
    ">=": operator.ge,
    "<": operator.lt,
    "<=": operator.le,
    "==": operator.eq,
    "!=": operator.ne,
}
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


class _Node(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FeatureCmp(_Node):
    feature: str
    op: Op
    value: float

    @model_validator(mode="after")
    def _known(self) -> FeatureCmp:
        if self.feature not in FEATURES:
            raise ValueError(f"unknown feature {self.feature!r}")
        return self


class ZCmp(_Node):
    z: str
    op: Op
    value: float

    @model_validator(mode="after")
    def _known(self) -> ZCmp:
        if self.z not in FEATURES:
            raise ValueError(f"unknown feature {self.z!r}")
        return self


class AllOf(_Node):
    all: list[Condition] = Field(min_length=1)


class AnyOf(_Node):
    any: list[Condition] = Field(min_length=1)


class NotOf(_Node):
    not_: Condition = Field(alias="not")


Condition = Union[AllOf, AnyOf, NotOf, FeatureCmp, ZCmp]  # noqa: UP007 - recursive alias
AllOf.model_rebuild()
AnyOf.model_rebuild()
NotOf.model_rebuild()


class Evidence(BaseModel):
    kind: Literal["feature", "z"]
    name: str
    observed: float
    op: Op
    threshold: float


def evaluate(cond: Condition, vector: Vector, z: dict[str, float]) -> tuple[bool, list[Evidence]]:
    """Return (matched, evidence for the comparisons that made it match)."""
    if isinstance(cond, FeatureCmp):
        observed = float(vector.get(cond.feature, 0.0))
        ok = _OPS[cond.op](observed, cond.value)
        return ok, [
            Evidence(
                kind="feature",
                name=cond.feature,
                observed=observed,
                op=cond.op,
                threshold=cond.value,
            )
        ] if ok else []
    if isinstance(cond, ZCmp):
        if cond.z not in z:  # no baseline yet: z-conditions cannot hold
            return False, []
        observed = float(z[cond.z])
        ok = _OPS[cond.op](observed, cond.value)
        return ok, [
            Evidence(kind="z", name=cond.z, observed=observed, op=cond.op, threshold=cond.value)
        ] if ok else []
    if isinstance(cond, AllOf):
        evidence: list[Evidence] = []
        for child in cond.all:
            ok, ev = evaluate(child, vector, z)
            if not ok:
                return False, []
            evidence += ev
        return True, evidence
    if isinstance(cond, AnyOf):
        for child in cond.any:
            ok, ev = evaluate(child, vector, z)
            if ok:
                return True, ev
        return False, []
    ok, _ = evaluate(cond.not_, vector, z)
    return (not ok), []


class Rule(_Node):
    id: str = Field(pattern=r"^[a-z0-9_]{3,64}$")
    title: str = Field(max_length=120)
    severity: Literal["low", "medium", "high", "critical"]
    techniques: list[str] = Field(min_length=1)
    rationale: str = Field(min_length=20)
    when: Condition | None = None
    source: Literal["traffic", "wifi"] = "traffic"

    @model_validator(mode="after")
    def _check(self) -> Rule:
        bad = [t for t in self.techniques if not _TECHNIQUE.fullmatch(t)]
        if bad:
            raise ValueError(f"invalid technique ids {bad}")
        if self.source == "traffic" and self.when is None:
            raise ValueError("traffic rules need a `when` condition")
        return self


class RuleHit(BaseModel):
    rule_id: str
    title: str
    severity: str
    techniques: list[str]
    rationale: str
    evidence: list[Evidence]


class RulesFile(_Node):
    rules: list[Rule]

    @model_validator(mode="after")
    def _unique(self) -> RulesFile:
        ids = [r.id for r in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate rule ids")
        return self


class RuleEngine:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules
        self.by_id = {r.id: r for r in rules}

    @classmethod
    def load(cls, path: Path) -> RuleEngine:
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
        return cls(RulesFile.model_validate(raw).rules)

    def evaluate(self, vector: Vector, z: dict[str, float]) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for rule in self.rules:
            if rule.source != "traffic" or rule.when is None:
                continue
            ok, evidence = evaluate(rule.when, vector, z)
            if ok:
                hits.append(
                    RuleHit(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        techniques=list(rule.techniques),
                        rationale=rule.rationale,
                        evidence=evidence,
                    )
                )
        return hits
