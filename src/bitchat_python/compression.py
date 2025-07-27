from typing import Tuple

try:
    import lz4.frame  # type: ignore[import-untyped,import-not-found]

    COMPRESSION_THRESHOLD = 100

    def compress_if_beneficial(data: bytes) -> Tuple[bytes, bool]:
        """Compress data if it reduces size"""
        if len(data) < COMPRESSION_THRESHOLD:
            return data, False

        compressed = lz4.frame.compress(data)
        if len(compressed) < len(data):
            return compressed, True
        else:
            return data, False

    def decompress(data: bytes) -> bytes:
        """Decompress LZ4 data"""
        try:
            return lz4.frame.decompress(data)
        except Exception as e:
            raise ValueError(f"Decompression failed: {e}")

except ImportError:
    # fallback to zlib
    import zlib

    def compress_if_beneficial(data: bytes) -> Tuple[bytes, bool]:
        """
        Compress data using zlib if it reduces size.
        Suitable for pure Python and many MicroPython environments.
        """
        if len(data) < COMPRESSION_THRESHOLD:
            return data, False

        # Using zlib.compressobj for more control, especially useful if
        # you want to stream data or handle larger chunks.
        # The default compression level is -1, which is a good balance.
        # Level 9 is best compression, 1 is fastest. Let's use 1 for speed
        # which is often preferred in embedded contexts if compression is needed.
        compressor = zlib.compressobj(level=1)
        compressed = compressor.compress(data)
        compressed += compressor.flush()  # Don't forget to flush remaining data

        if len(compressed) < len(data):
            return compressed, True
        else:
            return data, False

    def decompress(data: bytes) -> bytes:
        """
        Decompress zlib data.
        Suitable for pure Python and many MicroPython environments.
        """
        try:
            # zlib.decompress handles the entire compressed data block
            return zlib.decompress(data)
        except zlib.error as e:  # Catch zlib's specific error for better clarity
            raise ValueError(f"Decompression failed: {e}")
        except Exception as e:  # Catch other potential exceptions
            raise ValueError(f"Decompression failed with unexpected error: {e}")


# Export functions
__all__ = ("compress_if_beneficial", "decompress", "COMPRESSION_THRESHOLD")
