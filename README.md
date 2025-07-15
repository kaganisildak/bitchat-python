# BitChat Python

A Python implementation of the BitChat decentralized, peer-to-peer, encrypted chat application over BLE.

*This project is a rewrite of the [original Rust-based `bitchat-terminal`](https://github.com/ShilohEye/bitchat-terminal).*

## Table of contents
* [Installation](#installation)
* [Simple start](#simple-start)
* [Clone, Develop and Build](#clone-develop-and-build)
  * [Setup environment](#clone-and-setup-editable-environment-using-uv)
  * [Build](#build-sdist-and-wheel)

## Installation
With pip
```shell
pip install git+https://github.com/kaganisildak/bitchat-python
```

With [`uv` package and project manager](https://docs.astral.sh/uv/)
```Shell
uv tool install git+https://github.com/kaganisildak/bitchat-python.git
```

With [`pipx` standalone python apps panager](https://github.com/pypa/pipx)
```Shell
pipx install git+https://github.com/kaganisildak/bitchat-python.git
```


## Simple start
Installed with `pip`, `uv tool`, `pipx` 
```Shell
bitchat-python
```

With `uvx` command
> [!NOTE]
> This will only work once the project is published to the PyPI index.
```Shell
uvx bitchat-python
```


## Clone, Develop and Build
> [!TIP]  
> [`uv` package and project manager](https://docs.astral.sh/uv/) usage recommended for this step

### Clone and setup editable environment using `uv`
```Shell
git clone https://github.com/kaganisildak/bitchat-python.git
cd bitchat-python
uv sync --dev
.venv/bin/activate
```

### Type checking with
```Shell
uv run mypy 
```

### Linting and Formatting
Lint
```Shell
uv run ruff check
```

Format
```Shell
uv run ruff format
```

### Build sdist and wheel
```Shell
uv build
```




[//]: # (Old README.md content)
[//]: # (pip install bleak>=0.22.3 cryptography>=44.0.0 lz4>=4.3.3 aioconsole>=0.8.1 pybloom-live>=4.0.0)