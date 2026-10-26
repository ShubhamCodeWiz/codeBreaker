"""Shared fixtures for the target app test suite."""

import copy
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from target_app import main


@pytest.fixture(autouse=True)
def restore_state() -> Iterator[None]:
    """Snapshot module state before each test and restore it in place afterwards."""
    users = copy.deepcopy(main.USERS)
    transactions = copy.deepcopy(main.TRANSACTIONS)
    yield
    main.USERS.clear()
    main.USERS.update(users)
    main.TRANSACTIONS.clear()
    main.TRANSACTIONS.update(transactions)


@pytest_asyncio.fixture
async def client() -> AsyncIterator[AsyncClient]:
    """Async HTTP client bound to the ASGI app, no network involved."""
    transport = ASGITransport(app=main.app)
    async with AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client


@pytest.fixture
def auth_headers(client: AsyncClient) -> Callable[[str, str], Awaitable[dict[str, str]]]:
    """Return a helper that logs in as a user and yields bearer auth headers."""

    async def login(username: str = "alice", password: str = "password1") -> dict[str, str]:
        response = await client.post("/login", json={"username": username, "password": password})
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    return login