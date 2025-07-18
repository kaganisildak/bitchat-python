# BitChat Python

A Python implementation of the BitChat decentralized, peer-to-peer, encrypted chat application over BLE.

*This project is a rewrite of the [original Rust-based `bitchat-terminal`](https://github.com/ShilohEye/bitchat-terminal).*

## Table of contents
* [Installation](#installation)
* [Usage](#usage)
  * [Simple start](#simple-start)
  * [CLI startup options](#cli-startup-args)
  * [BitChat Commands](#bitchat-commands)
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


## Usage

### Simple start
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

### CLI startup options
```shell
  -h, --help     show this help message and exit
  -d, --debug    enable BASIC debug (connection info)
  -v, --verbose  enable FULL debug (verbose output)
  -u, --usage    show usage info
  -V, --version  show program`s version number and exit
  --log [LOG]    log file path. If no path is provided, logs to 'bitchat.log'. If --log is omitted, no logging occurs.
```

### BitChat Commands

This section details the various commands available within BitChat.
```shell
General Commands

* `/help`               : Show this help menu
* `/h`                  : Alias for /help
* `/me`                 : Get your Nickname and peer_id
* `/name <name>`        : Change your nickname
* `/status`             : Show connection info
* `/clear`              : Clear the screen
* `/exit`               : Quit BitChat
*  `/q`                 : Alias for /exit


Navigation Commands

* `1-9`                 : Quick switch to conversation
* `/list`               : Show all conversations
* `/switch`             : Interactive conversation switcher
* `/public`             : Go to public chat


Messaging Commands

(Type normally to send in current mode)

* `/dm <name>`          : Start private conversation
* `/dm <name> <msg>`    : Send quick private message
* `/reply`              : Reply to last private message


Channel Commands

* `/j #channel`               : Join or create a channel
* `/j #channel <password>`    : Join with password
* `/leave`                    : Leave current channel
* `/pass <pwd>`               : Set channel password (owner only)
* `/transfer @user`           : Transfer ownership (owner only)


Discovery Commands

* `/channels`                 : List all discovered channels
* `/online`                   : Show who`s online
* `/w`                        : Alias for /online


Privacy & Security Commands

* `/block @user`       : Block a user
* `/block`             : List blocked users
* `/unblock @user`     : Unblock a user
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