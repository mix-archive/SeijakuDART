import asyncio
from collections.abc import AsyncIterator, Awaitable
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

    def __str__(self) -> str:
        if ":" in self.host and not self.host.startswith("["):
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"


async def join_async_streams[T](*streams: AsyncIterator[T]):
    wait_tasks = {asyncio.ensure_future(anext(stream)): stream for stream in streams}
    while wait_tasks:
        done, _ = await asyncio.wait(wait_tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            if isinstance(task.exception(), StopAsyncIteration):
                return
            stream = wait_tasks.pop(task)
            yield stream, task.result()
            wait_tasks[asyncio.ensure_future(anext(stream))] = stream
    return
