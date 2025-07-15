from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

DATETIME_FORMAT = "%H:%M:%S"


class ChatMode(Enum):
    """Chat modes enumeration"""

    Public = auto()
    Channel = auto()
    PrivateDM = auto()


@dataclass
class Chat:
    """Keeps chat mode, user or channel name, and peer_id"""

    mode: ChatMode = field(default=ChatMode.Public)  # chat mode aka type
    name: Optional[str] = field(
        default=None
    )  # unified attribute for nickname/channel_name
    peer_id: Optional[str] = field(default=None)

    @classmethod
    def pub(cls) -> "Chat":
        """Factory method to create public chat instance"""
        return cls(ChatMode.Public)

    @classmethod
    def chan(cls, channame: str) -> "Chat":
        """Factory method to create channel chat instance"""
        return cls(ChatMode.Channel, name=channame)

    @classmethod
    def private(cls, nickname: str, peer_id: str) -> "Chat":
        """Factory method to create private chat instance"""
        return cls(ChatMode.PrivateDM, name=nickname, peer_id=peer_id)


@dataclass
class ChatContext:
    current_chat: Chat = field(default_factory=Chat.pub)
    active_channels: List[str] = field(default_factory=list)
    active_dms: Dict[str, str] = field(default_factory=dict)  # nickname -> peer_id
    last_private_sender: Optional[Tuple[str, str]] = None

    def format_prompt(self) -> str:
        if self.current_chat.mode is ChatMode.Public:
            return "[Public]"
        elif self.current_chat.mode is ChatMode.Channel:
            return f"[{self.current_chat.name}]"
        elif self.current_chat.mode is ChatMode.PrivateDM:
            return f"[DM: {self.current_chat.name}]"
        return ">"

    def get_status_line(self) -> str:
        parts = ["[1] Public"]

        for i, channel in enumerate(self.active_channels):
            parts.append(f"[{i + 2}] {channel}")

        dm_start = 2 + len(self.active_channels)
        for i, (nick, _) in enumerate(self.active_dms.items()):
            parts.append(f"[{i + dm_start}] DM:{nick}")

        return f"Active: {' '.join(parts)}"

    def switch_to_number(self, num: int) -> bool:
        if num == 1:
            self.current_chat = Chat.pub()
            print("\033[90m─────────────────────────\033[0m")
            print(
                "\033[90m» Switched to Public chat. Just type to send messages.\033[0m"
            )
            return True

        channel_end = 1 + len(self.active_channels)
        if 1 < num <= channel_end:
            channel_idx = num - 2
            if channel_idx < len(self.active_channels):
                channel = self.active_channels[channel_idx]
                self.current_chat = Chat.chan(channel)
                print("\033[90m─────────────────────────\033[0m")
                print(f"\033[90m» Switched to channel {channel}\033[0m")
                return True

        dm_start = channel_end + 1
        dm_idx = num - dm_start
        dm_list = list(self.active_dms.items())
        if dm_idx < len(dm_list):
            nick, peer_id = dm_list[dm_idx]
            self.current_chat = Chat.private(nick, peer_id)
            print("\033[90m─────────────────────────\033[0m")
            print(
                f"\033[90m» Switched to DM with {nick}. Just type to send messages.\033[0m"
            )
            return True

        return False

    def add_channel(self, channel: str) -> None:
        if channel not in self.active_channels:
            self.active_channels.append(channel)

    def add_dm(self, nickname: str, peer_id: str) -> None:
        self.active_dms[nickname] = peer_id

    def enter_dm_mode(self, nickname: str, peer_id: str) -> None:
        self.add_dm(nickname, peer_id)
        self.current_chat = Chat.private(nickname, peer_id)
        print("\033[90m─────────────────────────\033[0m")
        print(
            f"\033[90m» Entered DM mode with {nickname}. Just type to send messages.\033[0m"
        )

    def switch_to_channel(self, channel: str) -> None:
        self.add_channel(channel)
        self.current_chat = Chat.chan(channel)
        print("\033[90m─────────────────────────\033[0m")
        print(f"\033[90m» Switched to channel {channel}\033[0m")

    def switch_to_channel_silent(self, channel: str) -> None:
        self.add_channel(channel)
        self.current_chat = Chat.chan(channel)

    def switch_to_public(self) -> None:
        self.current_chat = Chat.pub()
        print("\033[90m─────────────────────────\033[0m")
        print("\033[90m» Switched to Public chat. Just type to send messages.\033[0m")

    def remove_channel(self, channel: str) -> None:
        if channel in self.active_channels:
            self.active_channels.remove(channel)

    def show_conversation_list(self) -> None:
        print("\n╭─── Active Conversations ───╮")
        print("│                            │")

        # Public
        indicator = "→" if self.current_chat.mode is ChatMode.Public else " "
        print(f"│ {indicator} [1] Public               │")

        # Channels
        num = 2
        for channel in self.active_channels:
            is_current = (
                self.current_chat is ChatMode.Channel
                and self.current_chat.name == channel
            )
            indicator = "→" if is_current else " "
            padding = " " * (18 - len(channel))
            print(f"│ {indicator} [{num}] {channel}{padding}│")
            num += 1

        # DMs
        for nick, _ in self.active_dms.items():
            is_current = (
                self.current_chat.mode is ChatMode.PrivateDM
                and self.current_chat.name == nick
            )
            indicator = "→" if is_current else " "
            dm_text = f"DM: {nick}"
            padding = " " * (18 - len(dm_text))
            print(f"│ {indicator} [{num}] {dm_text}{padding}│")
            num += 1

        print("│                            │")
        print("╰────────────────────────────╯")

    def get_conversation_list_with_numbers(self) -> str:
        output = "╭─── Select Conversation ───╮\n"

        # Public
        output += "│  1. Public                │\n"

        # Channels
        num = 2
        for channel in self.active_channels:
            padding = " " * (20 - len(channel))
            output += f"│  {num}. {channel}{padding}│\n"
            num += 1

        # DMs
        for nick, _ in self.active_dms.items():
            dm_text = f"DM: {nick}"
            padding = " " * (20 - len(dm_text))
            output += f"│  {num}. {dm_text}{padding}│\n"
            num += 1

        output += "╰───────────────────────────╯"
        return output


def format_message_display(
    timestamp: datetime,
    sender: str,
    content: str,
    is_private: bool,
    is_channel: bool,
    channel_name: Optional[str],
    recipient: Optional[str],
    my_nickname: str,
) -> str:
    """Format a message for display"""
    time_str = timestamp.strftime(DATETIME_FORMAT)

    if is_private:
        # Orange for private messages (matching iOS)
        if sender == my_nickname:
            # Message I sent - use brighter orange
            if recipient:
                return f"\033[2;38;5;208m[{time_str}|DM]\033[0m \033[38;5;214m<you → @{recipient}>\033[0m {content}"
            else:
                return f"\033[2;38;5;208m[{time_str}|DM]\033[0m \033[38;5;214m<you → ???>\033[0m {content}"
        else:
            # Message I received - use normal orange
            return f"\033[2;38;5;208m[{time_str}|DM]\033[0m \033[38;5;208m<@{sender} → you>\033[0m {content}"
    elif is_channel:
        # Blue for channel messages (matching iOS)
        if sender == my_nickname:
            # My messages - light blue (256-color)
            if channel_name:
                return f"\033[2;34m[{time_str}|{channel_name}]\033[0m \033[38;5;117m<@{sender} @ {channel_name}>\033[0m {content}"
            else:
                return f"\033[2;34m[{time_str}|Ch]\033[0m \033[38;5;117m<@{sender} @ ???>\033[0m {content}"
        else:
            # Other users - normal blue
            if channel_name:
                return f"\033[2;34m[{time_str}|{channel_name}]\033[0m \033[34m<@{sender} @ {channel_name}>\033[0m {content}"
            else:
                return f"\033[2;34m[{time_str}|Ch]\033[0m \033[34m<@{sender} @ ???>\033[0m {content}"
    else:
        # Public message - green for metadata
        if sender == my_nickname:
            # My messages - light green (256-color)
            return f"\033[2;32m[{time_str}]\033[0m \033[38;5;120m<@{sender}>\033[0m {content}"
        else:
            # Other users - normal green
            return f"\033[2;32m[{time_str}]\033[0m \033[32m<@{sender}>\033[0m {content}"


def get_usage() -> str:
    """
    Returns the BitChat help menu as a multi-line string literal.
    """
    usage_menu = (
        "\n\033[38;5;46m━━━ BitChat Commands ━━━\033[0m\n"
        "\n"
        # General
        "\033[38;5;40m▶ General\033[0m\n"
        "  \033[36m/help\033[0m         Show this help menu\n"
        "  \033[36m/h\033[0m            Alias for /help\n"
        "  \033[36m/me\033[0m           Get your Nickname and ID\n"
        "  \033[36m/name\033[0m \033[90m<name>\033[0m  Change your nickname\n"
        "  \033[36m/status\033[0m       Show connection info\n"
        "  \033[36m/clear\033[0m        Clear the screen\n"
        "  \033[36m/exit\033[0m         Quit BitChat\n"
        "  \033[36m/q\033[0m            Alias for /exit\n"
        "\n"
        # Navigation
        "\033[38;5;40m▶ Navigation\033[0m\n"
        "  \033[36m1-9\033[0m           Quick switch to conversation\n"
        "  \033[36m/list\033[0m         Show all conversations\n"
        "  \033[36m/switch\033[0m       Interactive conversation switcher\n"
        "  \033[36m/public\033[0m       Go to public chat\n"
        "\n"
        # Messaging
        "\033[38;5;40m▶ Messaging\033[0m\n"
        "  \033[90m(type normally to send in current mode)\033[0m\n"
        "  \033[36m/dm\033[0m \033[90m<name>\033[0m    Start private conversation\n"
        "  \033[36m/dm\033[0m \033[90m<name> <msg>\033[0m Send quick private message\n"
        "  \033[36m/reply\033[0m        Reply to last private message\n"
        "\n"
        # Channels
        "\033[38;5;40m▶ Channels\033[0m\n"
        "  \033[36m/j\033[0m \033[90m#channel\033[0m   Join or create a channel\n"
        "  \033[36m/j\033[0m \033[90m#channel <password>\033[0m Join with password\n"
        "  \033[36m/leave\033[0m        Leave current channel\n"
        "  \033[36m/pass\033[0m \033[90m<pwd>\033[0m   Set channel password (owner only)\n"
        "  \033[36m/transfer\033[0m \033[90m@user\033[0m Transfer ownership (owner only)\n"
        "\n"
        # Discovery
        "\033[38;5;40m▶ Discovery\033[0m\n"
        "  \033[36m/channels\033[0m     List all discovered channels\n"
        "  \033[36m/online\033[0m       Show who's online\n"
        "  \033[36m/w\033[0m            Alias for /online\n"
        "\n"
        # Privacy & Security
        "\033[38;5;40m▶ Privacy & Security\033[0m\n"
        "  \033[36m/block\033[0m \033[90m@user\033[0m  Block a user\n"
        "  \033[36m/block\033[0m        List blocked users\n"
        "  \033[36m/unblock\033[0m \033[90m@user\033[0m Unblock a user\n"
        "\n"
        "\033[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    )
    return usage_menu


def print_usage() -> None:
    """Print help menu"""
    print(get_usage())


def clear_screen() -> None:
    """Clear the terminal screen"""
    print("\033[2J\033[1;1H", end="")


# Export classes
__all__ = (
    "DATETIME_FORMAT",
    "ChatMode",
    "Chat",
    "ChatContext",
    "format_message_display",
    "get_usage",
    "print_usage",
    "clear_screen",
)
