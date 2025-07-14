import os
from enum import IntEnum
from dataclasses import dataclass
from typing import List

MAX_FRAGMENT_SIZE = 500

class FragmentType(IntEnum):
    START = 0x05
    CONTINUE = 0x06
    END = 0x07

@dataclass
class Fragment:
    fragment_id: bytes
    fragment_type: FragmentType
    index: int
    total: int
    original_type: int
    data: bytes

def fragment_payload(payload: bytes, original_msg_type: int) -> List[Fragment]:
    """Fragment a large payload"""
    if len(payload) <= MAX_FRAGMENT_SIZE:
        return []
    
    fragment_id = os.urandom(8)
    chunks = [payload[i:i+MAX_FRAGMENT_SIZE] for i in range(0, len(payload), MAX_FRAGMENT_SIZE)]
    total = len(chunks)
    
    fragments = []
    for i, chunk in enumerate(chunks):
        if i == 0:
            fragment_type = FragmentType.START
        elif i == len(chunks) - 1:
            fragment_type = FragmentType.END
        else:
            fragment_type = FragmentType.CONTINUE
        
        fragments.append(Fragment(
            fragment_id=fragment_id,
            fragment_type=fragment_type,
            index=i,
            total=total,
            original_type=original_msg_type,
            data=chunk
        ))
    
    return fragments

# Export classes and functions
__all__ = ['Fragment', 'FragmentType', 'fragment_payload', 'MAX_FRAGMENT_SIZE']