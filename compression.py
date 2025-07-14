from typing import Tuple

import lz4.frame

COMPRESSION_THRESHOLD = 100

def compress_if_beneficial(data: bytes) -> Tuple[bytes, bool]:
    """Compress data if it reduces size"""
    if len(data) < COMPRESSION_THRESHOLD:
        return (data, False)
    
    compressed = lz4.frame.compress(data)
    if len(compressed) < len(data):
        return (compressed, True)
    else:
        return (data, False)

def decompress(data: bytes) -> bytes:
    """Decompress LZ4 data"""
    try:
        return lz4.frame.decompress(data)
    except Exception as e:
        raise ValueError(f"Decompression failed: {e}")

# Export functions
__all__ = ['compress_if_beneficial', 'decompress', 'COMPRESSION_THRESHOLD']