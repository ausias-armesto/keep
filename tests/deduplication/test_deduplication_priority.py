"""
Tests for deduplication rule priority: ordering in rule selection, persistence
through the API, and integration with alert fingerprint computation.
"""
import time

import pytest

from keep.api.core.db import create_deduplication_rule, get_custom_deduplication_rule
from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.api.models.db.alert import AlertDeduplicationRule
from keep.providers.providers_factory import ProvidersFactory
from tests.fixtures.client import client, setup_api_key, test_app  # noqa


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_rule(name, provider_type, fingerprint_fields, priority):
    """Create an AlertDeduplicationRule and return it (no cross-session refresh)."""
    return create_deduplication_rule(
        tenant_id=SINGLE_TENANT_UUID,
        name=name,
        description=f"Test rule: {name}",
        provider_id=None,
        provider_type=provider_type,
        created_by="test@keep.dev",
        fingerprint_fields=fingerprint_fields,
        full_deduplication=False,
        ignore_fields=[],
        priority=priority,
    )


def _register_datadog_linked_provider(client):
    """Send one Datadog alert so Keep registers it as a linked provider."""
    provider = ProvidersFactory.get_provider_class("datadog")
    alert = provider.simulate_alert()
    client.post(
        "/alerts/event/datadog", json=alert, headers={"x-api-key": "some-api-key"}
    )
    time.sleep(1)


def wait_for_alerts(client, num_alerts, timeout=15):
    start = time.time()
    while time.time() - start < timeout:
        alerts = client.get("/alerts", headers={"x-api-key": "some-api-key"}).json()
        if len(alerts) >= num_alerts:
            return alerts
        time.sleep(0.3)
    raise TimeoutError(f"Expected {num_alerts} alerts, got {len(alerts)}")


# ---------------------------------------------------------------------------
# Unit-level DB tests (no HTTP client needed)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "test_app",
    [{"AUTH_TYPE": "NOAUTH"}],
    indirect=True,
)
def test_highest_priority_rule_selected(db_session, test_app):
    """get_custom_deduplication_rule returns the rule with the highest priority."""
    low = _create_rule("low-priority", "prometheus", ["alertname"], priority=0)
    high = _create_rule(
        "high-priority", "prometheus", ["startsAt", "fingerprint"], priority=5
    )

    selected = get_custom_deduplication_rule(
        tenant_id=SINGLE_TENANT_UUID,
        provider_id=None,
        provider_type="prometheus",
    )

    assert selected is not None
    assert selected.id == high.id
    assert selected.name == "high-priority"
    assert selected.fingerprint_fields == ["startsAt", "fingerprint"]


@pytest.mark.parametrize(
    "test_app",
    [{"AUTH_TYPE": "NOAUTH"}],
    indirect=True,
)
def test_single_rule_always_selected(db_session, test_app):
    """When only one rule exists it is always returned regardless of priority."""
    rule = _create_rule("only-rule", "prometheus", ["fingerprint"], priority=0)

    selected = get_custom_deduplication_rule(
        tenant_id=SINGLE_TENANT_UUID,
        provider_id=None,
        provider_type="prometheus",
    )

    assert selected is not None
    assert selected.id == rule.id


@pytest.mark.parametrize(
    "test_app",
    [{"AUTH_TYPE": "NOAUTH"}],
    indirect=True,
)
def test_no_rule_returns_none(db_session, test_app):
    """get_custom_deduplication_rule returns None when no rules exist."""
    selected = get_custom_deduplication_rule(
        tenant_id=SINGLE_TENANT_UUID,
        provider_id=None,
        provider_type="prometheus",
    )
    assert selected is None


@pytest.mark.parametrize(
    "test_app",
    [{"AUTH_TYPE": "NOAUTH"}],
    indirect=True,
)
def test_tie_in_priority_returns_a_rule(db_session, test_app):
    """When two rules share the same priority, one is returned (not None)."""
    _create_rule("rule-a", "prometheus", ["alertname"], priority=1)
    _create_rule("rule-b", "prometheus", ["fingerprint"], priority=1)

    selected = get_custom_deduplication_rule(
        tenant_id=SINGLE_TENANT_UUID,
        provider_id=None,
        provider_type="prometheus",
    )
    assert selected is not None
    assert selected.name in ("rule-a", "rule-b")
