from importlib import metadata

try:
    __version__ = metadata.version("bitchat-python")
except metadata.PackageNotFoundError:
    __version__ = "unknown"

__all__ = ("__version__",)
