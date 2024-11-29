import asyncio
import contextlib
import itertools
import logging
import time
import uuid
from collections.abc import Callable
from enum import IntEnum, auto
from functools import cached_property
from typing import cast

from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
from cryptography.hazmat.primitives.ciphers import Cipher
from fastcrc import crc64

from ..utils import AddressTuple

TAG_SIZE = 8

logger = logging.getLogger(__name__)


class ClientProtocolState(IntEnum):
    ESTABLISHING = auto()
    HANDSHAKE = auto()
    CONNECTED = auto()


class ControlServerProtocol(asyncio.Protocol):
    def __init__(
        self,
        protocol_factory: Callable[[], asyncio.Protocol],
        list_encryption_keys: Callable[[], dict[uuid.UUID, str]],
        client_time_tolerance: int = 30,
    ):
        self.sub_protocol = protocol_factory()
        self.sub_transport: ControlClientTransport | None = None

        # returns dict[client_id, encryption_key]
        self.list_encryption_keys = list_encryption_keys
        self.client_time_tolerance = client_time_tolerance
        self.state = ClientProtocolState.ESTABLISHING
        self.cipher: Cipher[None] | None = None

    @cached_property
    def encryptor(self):
        if self.cipher is None:
            raise ValueError("Cipher not initialized")
        return self.cipher.encryptor()

    @cached_property
    def decryptor(self):
        if self.cipher is None:
            raise ValueError("Cipher not initialized")
        return self.cipher.decryptor()

    @property
    def peername(self):
        return AddressTuple.from_transport(self.transport)

    def connection_made(self, transport):
        self.transport = cast(asyncio.Transport, transport)
        self.state = ClientProtocolState.HANDSHAKE
        logger.info("Connection made from %s", self.peername)

    def _try_sub_protocol[**P, R](
        self, func: Callable[P, R], *args: P.args, **kwargs: P.kwargs
    ) -> R | None:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.exception(
                "Error occurred in sub protocol method %r",
                getattr(func, "__name__", func),
            )
            self.sub_protocol.connection_lost(e)
            self.transport.close()
        return

    def _check_handshake(self, tag: bytes):
        tag_value = int.from_bytes(tag, "big")
        connection_time = int(time.time())
        for (name, key), client_time in itertools.product(
            self.list_encryption_keys().items(),
            range(
                connection_time - self.client_time_tolerance,
                connection_time + self.client_time_tolerance,
            ),
        ):
            if crc64.ecma_182(f"{key}{client_time}".encode()) == tag_value:
                return name, key, client_time
        return

    def data_received(self, data):
        if self.state is self.state.ESTABLISHING or self.transport is None:
            raise ValueError("Connection not established")

        if self.state is self.state.HANDSHAKE:
            tag, data = data[:TAG_SIZE], data[TAG_SIZE:]
            if (
                len(tag) < TAG_SIZE
                or (handshake_info := self._check_handshake(tag)) is None
            ):
                logging.warning("Invalid handshake from %s detected", self.peername)
                self.transport.close()
                return

            name, key, client_time = handshake_info
            logger.info(
                "Handshake successful from %s as %r at %s",
                self.peername,
                name,
                time.ctime(client_time),
            )
            mangled_key = bytes(ord(c) ^ tag[i % TAG_SIZE] for i, c in enumerate(key))
            self.cipher = Cipher(ARC4(mangled_key), None)
            self.state = ClientProtocolState.CONNECTED

            self.sub_transport = ControlClientTransport(
                {
                    "peername": self.peername,
                    "client": name,
                    "key": key,
                }
            )
            self.sub_transport.set_protocol(self)
            self.sub_protocol.connection_made(self.sub_transport)

        if not data:
            return

        logger.debug("Received %d bytes from %s", len(data), self.peername)
        decrypted = self.decryptor.update(data)
        self._try_sub_protocol(self.sub_protocol.data_received, decrypted)

    def pause_writing(self) -> None:
        return self._try_sub_protocol(self.sub_protocol.pause_writing)

    def resume_writing(self) -> None:
        return self._try_sub_protocol(self.sub_protocol.resume_writing)

    def eof_received(self) -> bool | None:
        logger.debug("EOF received from %s", self.peername)
        return self._try_sub_protocol(self.sub_protocol.eof_received)

    def connection_lost(self, exc):
        with contextlib.suppress(Exception):
            self.sub_protocol.connection_lost(None)

        if exc:
            logger.exception("Connection lost from %s:", self.peername, exc_info=exc)
        else:
            logger.info("Connection lost from %s", self.peername)

        if self.sub_transport:
            self.sub_transport.close()
        self.transport.close()


class ControlClientTransport(asyncio.WriteTransport):
    protocol: ControlServerProtocol

    def is_closing(self) -> bool:
        return self.protocol.transport.is_closing()

    def close(self) -> None:
        return self.protocol.transport.close()

    def set_protocol(self, protocol: asyncio.BaseProtocol):
        self.protocol = cast(ControlServerProtocol, protocol)

    def get_protocol(self) -> asyncio.BaseProtocol:
        return self.protocol

    def set_write_buffer_limits(self, high: int | None = None, low: int | None = None):
        return self.protocol.transport.set_write_buffer_limits(high, low)

    def get_write_buffer_size(self) -> int:
        return self.protocol.transport.get_write_buffer_size()

    def get_write_buffer_limits(self) -> tuple[int, int]:
        return self.protocol.transport.get_write_buffer_limits()

    def write(self, data) -> None:
        encrypted = self.protocol.encryptor.update(bytes(data))
        return self.protocol.transport.write(encrypted)

    def write_eof(self) -> None:
        return self.protocol.transport.write_eof()

    def can_write_eof(self) -> bool:
        return self.protocol.transport.can_write_eof()

    def abort(self) -> None:
        return self.protocol.transport.abort()
