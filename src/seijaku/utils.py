import asyncio
from collections.abc import Awaitable
from typing import Annotated, NamedTuple

from pydantic import Field

type PortNumber = Annotated[int, Field(gt=0, lt=65536)]


def create_background_task[T](coro: Awaitable[T]) -> asyncio.Task[T]:
    task = asyncio.ensure_future(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


_background_tasks = set[asyncio.Task]()


class AddressTuple(NamedTuple):
    host: str
    port: PortNumber

    @classmethod
    def from_transport(cls, transport: asyncio.Transport):
        host, port, *_ = transport.get_extra_info("peername")
        return cls(host, port)

    @property
    def is_ipv6(self) -> bool:
        return ":" in self.host

    def __str__(self) -> str:
        if self.is_ipv6 and not self.host.startswith("["):
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"
