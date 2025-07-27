"""Compatibility module"""

import asyncio
import sys

from bitchat_python._logger import logger

try:
    import aioconsole as _aioconsole

    _ainput = _aioconsole.ainput
except ImportError:
    _aioconsole = None
    _ainput = None


async def _ainput_fallback(prompt):
    # ainput() Fallback uses if aioconsole.ainput() raises TypeError, EOF
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, input, prompt)


# section to apply I/O patches for Pythonista iOS app
if "Pythonista3.app" in sys.executable:
    from bitchat_python._compat.pythonista import (
        pythonista_aioconsole_ainput_patched,
        pythonista_get_ansi_print,
    )

    # ainput() patch
    if _aioconsole is not None:
        _ainput = pythonista_aioconsole_ainput_patched

    # print() patch
    try:
        import console
        import builtins

        builtins.print = pythonista_get_ansi_print(console)
    except ImportError:
        # fallback to default print
        pass

# ainput() Fallback
if _ainput is None:
    _ainput = _ainput_fallback


async def ainput(prompt):
    global _ainput
    try:
        return await _ainput(prompt)
    except (EOFError, TypeError) as err:
        logger.warning(f"ainput error: {err}, fallback to executor")
        _ainput = _ainput_fallback
        raise


if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(ainput("> "))
