"""
Patches that allow using bitchat_python in Pythonista iOS app
"""

import re
import sys

import aioconsole as _aioconsole

_BASIC_ANSI_RGB = {
    30: (0, 0, 0),
    31: (128, 0, 0),
    32: (0, 128, 0),
    33: (128, 128, 0),
    34: (0, 0, 128),
    35: (128, 0, 128),
    36: (0, 128, 128),
    37: (192, 192, 192),
    90: (128, 128, 128),
    91: (255, 0, 0),
    92: (0, 255, 0),
    93: (255, 255, 0),
    94: (0, 0, 255),
    95: (255, 0, 255),
    96: (0, 255, 255),
    97: (255, 255, 255),
}

_ANSI_PATTERN = re.compile(r"\x1B\[[0-9;?]*[A-Za-z]")
_ALLOWED_PATTERN = re.compile(r"\x1B\[[0-9;]*m")


def ansi_to_rgb(code):
    if isinstance(code, str):
        m = re.match(r"(?:38|48);2;(\d+);(\d+);(\d+)", code)
        if m:
            return tuple(map(int, m.groups()))
        try:
            code = int(code)
        except ValueError:
            return None

    if code in _BASIC_ANSI_RGB:
        return _BASIC_ANSI_RGB[code]

    if 16 <= code <= 231:
        c = code - 16
        r = (c // 36) % 6
        g = (c // 6) % 6
        b = c % 6
        return (r * 51, g * 51, b * 51)

    if 232 <= code <= 255:
        gray = (code - 232) * 10 + 8
        return (gray, gray, gray)

    return None


async def pythonista_aioconsole_ainput_patched(
    prompt="", *, streams=None, use_stderr=False, loop=None
):
    """
    Asynchronous equivalent to *input*.
    Patched for Pythonista iOS app console compatibility
    """
    # Get standard streams
    if streams is None:
        streams = await _aioconsole.get_standard_streams(
            use_stderr=use_stderr, loop=loop
        )
    reader, writer = streams
    # Write prompt
    writer.write(prompt.encode())
    await writer.drain()
    # Get data
    data = await reader.readline()
    # Decode data
    data = data.decode()
    # Return or raise EOF

    # NOTE: pythonista console not handles "\n" on return
    # if not data.endswith("\n"):
    #     raise EOFError

    return data.rstrip("\n")


def pythonista_get_ansi_print(console):
    def _print(*objects, sep=" ", end="\n", file=None, flush=False):
        text = sep.join(str(obj) for obj in objects) + end

        ansi_regex = r"\x1b\[([\d;]+)m"
        parts = re.split(ansi_regex, text)

        for i, part in enumerate(parts):
            if i % 2 == 1:  # ANSI code block
                codes = part.split(";")
                for c in codes:
                    if c == "0":
                        console.set_color()
                        ...
                    else:
                        rgb = ansi_to_rgb(c)
                        if rgb:
                            console.set_color(*rgb)
                            ...
            else:
                # This is visible text (may contain non-color ANSI → remove them)
                visible = _ANSI_PATTERN.sub("", part)
                sys.stdout.write(visible)
                sys.stdout.flush()

    return _print
