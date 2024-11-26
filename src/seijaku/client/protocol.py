import asyncio
import contextlib
import itertools
import logging
import time
from collections.abc import Callable
from enum import IntEnum, auto
from functools import cached_property
from typing import cast

from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
from cryptography.hazmat.primitives.ciphers import Cipher
from fastcrc import crc64

TAG_SIZE = 8

logger = logging.getLogger(__name__)


class ClientProtocolState(IntEnum):
    ESTABLISHING = auto()
    HANDSHAKE = auto()
    CONNECTED = auto()


class SubProtocolError(RuntimeError):
    pass


class InvalidStateError(ValueError):
    pass


class InvalidHandshakeError(ValueError):
    pass


class ControlServerProtocol(asyncio.Protocol):
    def __init__(
        self,
        protocol_factory: Callable[[], asyncio.Protocol],
        list_encryption_keys: Callable[[], dict[str, str]],
        client_time_tolerance: int = 30,
    ):
        self.sub_protocol = protocol_factory()
        # returns dict[client_name, encryption_key]
        self.list_encryption_keys = list_encryption_keys
        self.client_time_tolerance = client_time_tolerance
        self.state = ClientProtocolState.ESTABLISHING
        self.cipher: Cipher[None] | None = None

    @cached_property
    def encryptor(self):
        if self.cipher is None:
            raise InvalidStateError("Cipher not initialized")
        return self.cipher.encryptor()

    @cached_property
    def decryptor(self):
        if self.cipher is None:
            raise InvalidStateError("Cipher not initialized")
        return self.cipher.decryptor()

    def connection_made(self, transport):
        self.transport = cast(asyncio.Transport, transport)
        self.state = ClientProtocolState.HANDSHAKE
        logger.info(
            "Connection made from %s:%d",
            *self.transport.get_extra_info("peername"),
        )

    def _try_sub_protocol[**P, R](
        self, func: Callable[P, R], *args: P.args, **kwargs: P.kwargs
    ) -> R:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.exception("Error occurred in sub protocol method %r", func.__name__)
            self.sub_protocol.connection_lost(e)
            raise SubProtocolError from e

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
        raise InvalidHandshakeError("Invalid handshake tag")

    def data_received(self, data):
        if self.state is self.state.ESTABLISHING:
            raise InvalidStateError("Connection not established")

        if self.state is self.state.HANDSHAKE:
            tag, data = data[:TAG_SIZE], data[TAG_SIZE:]

            if len(tag) < TAG_SIZE:
                raise InvalidHandshakeError("Invalid handshake tag")

            name, key, client_time = self._check_handshake(tag)
            logger.info(
                "Handshake successful from %s:%d as %s at %s",
                self.transport.get_extra_info("peername"),
                name,
                time.ctime(client_time),
            )
            self.cipher = Cipher(
                ARC4(bytes(ord(c) ^ tag[i % TAG_SIZE] for i, c in enumerate(key))),
                None,
            )
            self.state = ClientProtocolState.CONNECTED

            sub_transport = ControlClientTransport(
                {
                    "peername": self.transport.get_extra_info("peername"),
                    "sockname": self.transport.get_extra_info("sockname"),
                    "name": name,
                    "key": key,
                }
            )
            sub_transport.set_protocol(self)
            self.sub_protocol.connection_made(sub_transport)

        if not data:
            return

        logger.debug(
            "Received %d bytes from %s:%d",
            len(data),
            *self.transport.get_extra_info("peername"),
        )
        decrypted = self.decryptor.update(data)
        self._try_sub_protocol(self.sub_protocol.data_received, decrypted)

    def pause_writing(self) -> None:
        return self._try_sub_protocol(self.sub_protocol.pause_writing)

    def resume_writing(self) -> None:
        return self._try_sub_protocol(self.sub_protocol.resume_writing)

    def eof_received(self) -> bool | None:
        logger.debug(
            "EOF received from %s:%d", *self.transport.get_extra_info("peername")
        )
        return self._try_sub_protocol(self.sub_protocol.eof_received)

    def connection_lost(self, exc):
        with contextlib.suppress(Exception):
            self.sub_protocol.connection_lost(None)

        match exc:
            case SubProtocolError():
                pass
            case InvalidStateError() | InvalidHandshakeError():
                logger.error(
                    "Error occurred from %s:%d: %s",
                    *self.transport.get_extra_info("peername"),
                    exc,
                )
            case Exception():
                logger.exception(
                    "Unexpected error occurred from %s:%d",
                    *self.transport.get_extra_info("peername"),
                    exc_info=exc,
                )
        logger.info(
            "Connection lost from %s:%d",
            *self.transport.get_extra_info("peername"),
        )


class ControlClientTransport(asyncio.WriteTransport):
    protocol: ControlServerProtocol

    def set_protocol(self, protocol: asyncio.BaseProtocol):
        self.protocol = cast(ControlServerProtocol, protocol)

    def get_protocol(self) -> asyncio.BaseProtocol:
        return self.protocol

    def write(self, data) -> None:
        encrypted = self.protocol.encryptor.update(bytes(data))
        return self.protocol.transport.write(encrypted)

    def __getattr__(self, name: str):
        return getattr(self.protocol.transport, name)
