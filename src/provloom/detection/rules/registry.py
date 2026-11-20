from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from provloom.detection.compiler.postgres_backend import CompiledRuleArtifact, compile_rule_yaml
from provloom.detection.domain.rule import RuleSource
from provloom.normalization.interfaces import MappingSpecSummary


class BuiltinRuleRegistry:
    """Loads built-in Sigma/Custom YAML rules and caches compiled artifacts."""

    def __init__(
        self,
        mapping_specs: Sequence[MappingSpecSummary] | None = None,
        extra_rules_dir: str | Path | None = None,
    ) -> None:
        self._mapping_specs = tuple(mapping_specs or ())
        self._extra_dir = Path(extra_rules_dir) if extra_rules_dir else None
        self._cache: dict[tuple[str, str], CompiledRuleArtifact] = {}
        self._builtins: tuple[CompiledRuleArtifact, ...] | None = None

    def compile(
        self,
        raw_yaml: str,
        source_reference: str = "inline",
        source_hint: RuleSource | None = None,
    ) -> CompiledRuleArtifact:
        key = (source_reference, raw_yaml)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        art = compile_rule_yaml(
            raw_yaml=raw_yaml,
            source_reference=source_reference,
            source_hint=source_hint,
            mapping_specs=self._mapping_specs,
        )
        self._cache[key] = art
        return art

    def load_builtins(self) -> Sequence[CompiledRuleArtifact]:
        if self._builtins is not None:
            return self._builtins

        base_dir = Path(__file__).resolve().parent
        sigma_dir = base_dir / "sigma"
        custom_dir = base_dir / "custom"

        loaded: list[CompiledRuleArtifact] = []
        if sigma_dir.is_dir():
            for p in sorted((*sigma_dir.glob("*.yml"), *sigma_dir.glob("*.yaml"))):
                ref = f"provloom://builtin/sigma/{p.name}"
                loaded.append(
                    self.compile(
                        p.read_text(encoding="utf-8"),
                        source_reference=ref,
                        source_hint=RuleSource.SIGMA,
                    )
                )
        if custom_dir.is_dir():
            for p in sorted((*custom_dir.glob("*.yml"), *custom_dir.glob("*.yaml"))):
                ref = f"provloom://builtin/custom/{p.name}"
                loaded.append(
                    self.compile(
                        p.read_text(encoding="utf-8"),
                        source_reference=ref,
                        source_hint=RuleSource.CUSTOM,
                    )
                )
        if self._extra_dir and self._extra_dir.is_dir():
            for p in sorted((*self._extra_dir.rglob("*.yml"), *self._extra_dir.rglob("*.yaml"))):
                ref = f"file://{p.name}"
                loaded.append(self.compile(p.read_text(encoding="utf-8"), source_reference=ref))

        self._builtins = tuple(loaded)
        return self._builtins
