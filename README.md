# BitChat Lime Client

A Python implementation of the BitChat decentralized, peer-to-peer, encrypted chat application over BLE.

*This project is a wrapper/client of bitchat-python, which is rewrite of the [original Rust-based `bitchat-terminal`](https://github.com/ShilohEye/bitchat-terminal).*

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
```Shell
pip install bleak>=0.22.3 cryptography>=44.0.0 lz4>=4.3.3 aioconsole>=0.8.1 pybloom-live>=4.0.0 
```
## Usage

### Simple start
```Shell
python3 bitchat.py
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
* `/q`                 : Alias for /exit


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

