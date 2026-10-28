from __future__ import annotations

import pytest

from examples.common import make_guard
from examples.fixed_app.main import create_app as create_fixed_app
from tenant_isolation_kit import TenantPair
from tests.helpers import pair_for

pytest_plugins = ["pytester"]


@pytest.fixture
def tenant_pair() -> TenantPair:
    """Clients of a fresh fixed app, running under the strict runtime guard."""
    return pair_for(create_fixed_app(guard=make_guard(strict=True)))
