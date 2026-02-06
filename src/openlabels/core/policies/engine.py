"""
Policy evaluation engine.

Evaluates classified entities against policy packs to determine:
- Which regulations apply (HIPAA, GDPR, PCI-DSS, etc.)
- Combined risk level
- Required security controls
- Retention requirements
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, Sequence

from openlabels.core.policies.schema import (
    DataSubjectRights,
    EntityMatch,
    HandlingRequirements,
    PolicyCategory,
    PolicyMatch,
    PolicyPack,
    PolicyResult,
    PolicyTrigger,
    RetentionPolicy,
    RiskLevel,
)

logger = logging.getLogger(__name__)


# Risk level ordering for comparison
RISK_ORDER = {
    RiskLevel.MINIMAL: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


@dataclass
class EvaluationContext:
    """Context for policy evaluation."""

    # Entity types present (normalized to lowercase)
    entity_types: set[str] = field(default_factory=set)

    # Count of each entity type
    type_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Max confidence per entity type
    type_max_confidence: dict[str, float] = field(default_factory=dict)

    # All entities for detailed matching
    entities: list[EntityMatch] = field(default_factory=list)


class PolicyEngine:
    """
    Evaluates classification results against policy packs.

    Thread-safe and stateless - can be shared across agents.

    Usage:
        engine = PolicyEngine()
        engine.load_builtin_policies()  # Load HIPAA, GDPR, PCI, etc.
        engine.add_policy(custom_policy)

        # Evaluate entities from classification
        result = engine.evaluate(entities)

        if result.is_sensitive:
            print(f"Risk: {result.risk_level}")
            print(f"Categories: {result.categories}")
            print(f"Requires encryption: {result.requires_encryption}")
    """

    def __init__(self):
        self._policies: list[PolicyPack] = []
        self._policies_by_category: dict[PolicyCategory, list[PolicyPack]] = defaultdict(list)

    def add_policy(self, policy: PolicyPack) -> None:
        """Add a policy pack to the engine."""
        if not policy.enabled:
            logger.debug(f"Skipping disabled policy: {policy.name}")
            return

        self._policies.append(policy)
        self._policies_by_category[policy.category].append(policy)

        # Keep sorted by priority (higher first)
        self._policies.sort(key=lambda p: p.priority, reverse=True)

        logger.debug(f"Added policy: {policy.name} (category={policy.category.value})")

    def add_policies(self, policies: Sequence[PolicyPack]) -> None:
        """Add multiple policy packs."""
        for policy in policies:
            self.add_policy(policy)

    def remove_policy(self, name: str) -> bool:
        """Remove a policy by name."""
        for i, policy in enumerate(self._policies):
            if policy.name == name:
                self._policies.pop(i)
                self._policies_by_category[policy.category].remove(policy)
                return True
        return False

    def clear_policies(self) -> None:
        """Remove all policies."""
        self._policies.clear()
        self._policies_by_category.clear()

    @property
    def policy_count(self) -> int:
        """Get number of loaded policies."""
        return len(self._policies)

    @property
    def policy_names(self) -> list[str]:
        """Get names of all loaded policies."""
        return [p.name for p in self._policies]

    def evaluate(
        self,
        entities: Sequence[EntityMatch],
        min_confidence: float = 0.0,
    ) -> PolicyResult:
        """
        Evaluate entities against all policies.

        Args:
            entities: List of detected entities
            min_confidence: Minimum confidence threshold to consider

        Returns:
            PolicyResult with all matched policies and combined requirements
        """
        # Build evaluation context
        ctx = self._build_context(entities, min_confidence)

        if not ctx.entity_types:
            return PolicyResult()

        # Evaluate each policy
        result = PolicyResult()

        for policy in self._policies:
            match = self._evaluate_policy(policy, ctx)
            if match:
                result.matches.append(match)
                self._merge_policy_into_result(policy, result)

        # Set summary flags
        result.has_phi = PolicyCategory.HIPAA in result.categories or PolicyCategory.PHI in result.categories
        result.has_pii = PolicyCategory.PII in result.categories
        result.has_pci = PolicyCategory.PCI_DSS in result.categories
        result.has_gdpr_special = any(
            m.trigger_type == "special_category" for m in result.matches
        )

        return result

    def _build_context(
        self,
        entities: Sequence[EntityMatch],
        min_confidence: float,
    ) -> EvaluationContext:
        """Build evaluation context from entities."""
        ctx = EvaluationContext()

        for entity in entities:
            if entity.confidence < min_confidence:
                continue

            # Normalize entity type to lowercase
            etype = entity.entity_type.lower()

            ctx.entity_types.add(etype)
            ctx.type_counts[etype] += 1
            ctx.type_max_confidence[etype] = max(
                ctx.type_max_confidence.get(etype, 0.0),
                entity.confidence
            )
            ctx.entities.append(entity)

        return ctx

    def _evaluate_policy(
        self,
        policy: PolicyPack,
        ctx: EvaluationContext,
    ) -> Optional[PolicyMatch]:
        """Evaluate a single policy against the context."""
        triggers = policy.triggers

        if triggers.is_empty():
            return None

        # Check exclusions first
        if triggers.exclude_if_only:
            exclude_types = {t.lower() for t in triggers.exclude_if_only}
            if ctx.entity_types and ctx.entity_types.issubset(exclude_types):
                return None

        # Check any_of triggers
        if triggers.any_of:
            any_of_types = {t.lower() for t in triggers.any_of}
            matched = ctx.entity_types & any_of_types

            if matched:
                # Check confidence threshold
                if all(
                    ctx.type_max_confidence.get(t, 0) >= triggers.min_confidence
                    for t in matched
                ):
                    # Check count threshold
                    if all(ctx.type_counts[t] >= triggers.min_count for t in matched):
                        return PolicyMatch(
                            policy_name=policy.name,
                            trigger_type="any_of",
                            matched_entities=list(matched),
                            matched_values=self._get_matched_values(ctx, matched),
                        )

        # Check all_of triggers
        if triggers.all_of:
            all_of_types = {t.lower() for t in triggers.all_of}

            if all_of_types.issubset(ctx.entity_types):
                # Check confidence for all
                if all(
                    ctx.type_max_confidence.get(t, 0) >= triggers.min_confidence
                    for t in all_of_types
                ):
                    return PolicyMatch(
                        policy_name=policy.name,
                        trigger_type="all_of",
                        matched_entities=list(all_of_types),
                        matched_values=self._get_matched_values(ctx, all_of_types),
                    )

        # Check combination triggers (OR between combinations)
        if triggers.combinations:
            for combination in triggers.combinations:
                combo_types = {t.lower() for t in combination}

                if combo_types.issubset(ctx.entity_types):
                    # Check confidence for all in combination
                    if all(
                        ctx.type_max_confidence.get(t, 0) >= triggers.min_confidence
                        for t in combo_types
                    ):
                        return PolicyMatch(
                            policy_name=policy.name,
                            trigger_type="combination",
                            matched_entities=list(combo_types),
                            matched_values=self._get_matched_values(ctx, combo_types),
                        )

        # Check special category triggers
        if not policy.special_category_triggers.is_empty():
            special_match = self._evaluate_triggers(
                policy.special_category_triggers, ctx
            )
            if special_match:
                return PolicyMatch(
                    policy_name=policy.name,
                    trigger_type="special_category",
                    matched_entities=special_match,
                    matched_values=self._get_matched_values(ctx, set(special_match)),
                )

        return None

    def _evaluate_triggers(
        self,
        triggers: PolicyTrigger,
        ctx: EvaluationContext,
    ) -> Optional[list[str]]:
        """Evaluate triggers and return matched entity types if triggered."""
        if triggers.any_of:
            any_of_types = {t.lower() for t in triggers.any_of}
            matched = ctx.entity_types & any_of_types
            if matched:
                return list(matched)

        if triggers.all_of:
            all_of_types = {t.lower() for t in triggers.all_of}
            if all_of_types.issubset(ctx.entity_types):
                return list(all_of_types)

        if triggers.combinations:
            for combination in triggers.combinations:
                combo_types = {t.lower() for t in combination}
                if combo_types.issubset(ctx.entity_types):
                    return list(combo_types)

        return None

    def _get_matched_values(
        self,
        ctx: EvaluationContext,
        entity_types: set[str],
    ) -> list[str]:
        """Get redacted values for matched entities (for logging/audit)."""
        values = []
        for entity in ctx.entities:
            if entity.entity_type.lower() in entity_types:
                # Redact for privacy - show type and partial value
                value = entity.value
                if len(value) > 4:
                    redacted = value[:2] + "*" * (len(value) - 4) + value[-2:]
                else:
                    redacted = "*" * len(value)
                values.append(f"{entity.entity_type}:{redacted}")
        return values[:10]  # Limit for logging

    def _merge_policy_into_result(
        self,
        policy: PolicyPack,
        result: PolicyResult,
    ) -> None:
        """Merge policy requirements into result (most restrictive wins)."""
        # Category
        result.categories.add(policy.category)

        # Risk level (highest wins)
        if RISK_ORDER[policy.risk_level] > RISK_ORDER[result.risk_level]:
            result.risk_level = policy.risk_level

        # Handling requirements (any True wins)
        ph = policy.handling
        rh = result.handling
        rh.encryption_required = rh.encryption_required or ph.encryption_required
        rh.encryption_at_rest = rh.encryption_at_rest or ph.encryption_at_rest
        rh.encryption_in_transit = rh.encryption_in_transit or ph.encryption_in_transit
        rh.tokenization_required = rh.tokenization_required or ph.tokenization_required
        rh.masking_required = rh.masking_required or ph.masking_required
        rh.audit_access = rh.audit_access or ph.audit_access
        rh.access_logging = rh.access_logging or ph.access_logging
        rh.mfa_required = rh.mfa_required or ph.mfa_required

        # Geographic restrictions (intersection for allowed, union for prohibited)
        if ph.geographic_restrictions:
            if rh.geographic_restrictions:
                rh.geographic_restrictions = list(
                    set(rh.geographic_restrictions) & set(ph.geographic_restrictions)
                )
            else:
                rh.geographic_restrictions = ph.geographic_restrictions.copy()

        if ph.prohibited_regions:
            rh.prohibited_regions = list(
                set(rh.prohibited_regions) | set(ph.prohibited_regions)
            )

        # Retention (most restrictive)
        pr = policy.retention
        rr = result.retention

        # Longest minimum retention
        if pr.min_days is not None:
            if rr.min_days is None or pr.min_days > rr.min_days:
                rr.min_days = pr.min_days

        # Shortest maximum retention
        if pr.max_days is not None:
            if rr.max_days is None or pr.max_days < rr.max_days:
                rr.max_days = pr.max_days

        # Most frequent review
        if pr.review_frequency_days is not None:
            if rr.review_frequency_days is None or pr.review_frequency_days < rr.review_frequency_days:
                rr.review_frequency_days = pr.review_frequency_days

        # Data subject rights (union - if any policy grants a right, it's granted)
        pd = policy.data_subject_rights
        rd = result.data_subject_rights
        rd.access = rd.access or pd.access
        rd.rectification = rd.rectification or pd.rectification
        rd.erasure = rd.erasure or pd.erasure
        rd.portability = rd.portability or pd.portability
        rd.restriction = rd.restriction or pd.restriction
        rd.objection = rd.objection or pd.objection

        # Jurisdictions (union)
        result.jurisdictions.update(policy.jurisdictions)

    def get_policies_for_category(self, category: PolicyCategory) -> list[PolicyPack]:
        """Get all policies for a specific category."""
        return self._policies_by_category.get(category, [])

    def get_enabled_categories(self) -> set[PolicyCategory]:
        """Get all categories with at least one enabled policy."""
        return set(self._policies_by_category.keys())


# Global engine singleton
_engine_instance: Optional[PolicyEngine] = None


def get_policy_engine() -> PolicyEngine:
    """Get or create the global policy engine instance."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = PolicyEngine()
        # Load built-in policies
        from openlabels.core.policies.loader import load_builtin_policies
        _engine_instance.add_policies(load_builtin_policies())
    return _engine_instance


