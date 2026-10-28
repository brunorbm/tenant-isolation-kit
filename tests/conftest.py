from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest
from sqlalchemy import Engine

from examples.common import make_engine, make_guard
from examples.fixed_app.main import create_app as create_fixed_app
from tenant_isolation_kit import TenantPair
from tests.helpers import pair_for

pytest_plugins = ["pytester"]


@pytest.fixture
def new_engine() -> Iterator[Callable[[], Engine]]:
    """Factory of fresh seeded engines, each disposed when the test ends.

    The example apps keep their in-memory database on a single pooled sqlite
    connection. Disposing the engine closes it explicitly: since Python 3.13 an
    unclosed ``sqlite3.Connection`` emits a ResourceWarning when it is garbage
    collected, at whatever later test happens to trigger the collection.
    """
    engines: list[Engine] = []

    def new() -> Engine:
        engines.append(make_engine())
        return engines[-1]

    yield new
    for engine in engines:
        engine.dispose()


@pytest.fixture
def tenant_pair(new_engine: Callable[[], Engine]) -> TenantPair:
    """Clients of a fresh fixed app, running under the strict runtime guard."""
    return pair_for(create_fixed_app(new_engine(), guard=make_guard(strict=True)))
