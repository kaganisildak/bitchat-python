"""
Compression utilities for BitChat protocol compatibility.
Matches Swift CompressionUtil.swift implementation.
"""

import lz4.frame
from typing import Optional

class CompressionUtil:
    """LZ4 compression utilities matching Swift implementation"""
    
    # Compression threshold - don't compress if data is smaller than this
    COMPRESSION_THRESHOLD = 100  # bytes
    
    @classmethod
    def compress(cls, data: bytes) -> Optional[bytes]:
        """
        Compress data using LZ4 algorithm (fast compression/decompression).
        Returns None if compression is not beneficial.
        """
        # Skip compression for small data
        if len(data) < cls.COMPRESSION_THRESHOLD:
            return None
        
        try:
            compressed = lz4.frame.compress(data, compression_level=lz4.frame.COMPRESSIONLEVEL_FAST)
            
            # Only return compressed data if it's actually smaller
            if len(compressed) < len(data):
                return compressed
            else:
                return None
        except Exception:
            return None
    
    @classmethod
    def decompress(cls, compressed_data: bytes, original_size: int) -> Optional[bytes]:
        """
        Decompress LZ4 compressed data.
        original_size is the expected decompressed size for validation.
        """
        try:
            decompressed = lz4.frame.decompress(compressed_data)
            
            # Validate the decompressed size matches expectation
            if len(decompressed) == original_size:
                return decompressed
            else:
                return None
        except Exception:
            return None
    
    @classmethod
    def should_compress(cls, data: bytes) -> bool:
        """
        Helper to check if compression is worth it.
        Returns False if data is too small or appears already compressed.
        """
        # Don't compress if data is too small
        if len(data) < cls.COMPRESSION_THRESHOLD:
            return False
        
        # Simple entropy check - count unique bytes
        byte_frequency = {}
        for byte in data:
            byte_frequency[byte] = byte_frequency.get(byte, 0) + 1
        
        # If we have very high byte diversity, data is likely already compressed
        unique_byte_ratio = len(byte_frequency) / min(len(data), 256)
        return unique_byte_ratio < 0.9  # Compress if less than 90% unique bytes 