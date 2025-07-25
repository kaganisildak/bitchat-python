import asyncio

from bitchat_python import bitchat


def main() -> None:
    try:
        asyncio.run(bitchat.main())
    except KeyboardInterrupt:
        print("\n[+] Exiting...")


if __name__ == "__main__":
    main()
