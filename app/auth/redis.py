# app/auth/redis.py

from datetime import datetime, timezone
from typing import Optional, Dict

# Simple in-memory blacklist store for JWT IDs (jti)
# Key: jti (str), Value: expiration time (datetime)
_blacklist: Dict[str, datetime] = {}


def add_to_blacklist(jti: str, exp: Optional[datetime] = None) -> None:
    """
    Add a token ID (jti) to the blacklist until its expiration time.
    If no expiration is provided, we store it with "now" so that
    is_blacklisted() will treat it as currently invalid.
    """
    if exp is None:
        exp = datetime.now(timezone.utc)
    _blacklist[jti] = exp


def is_blacklisted(jti: str) -> bool:
    """
    Check whether a token ID (jti) is blacklisted.
    Expired blacklist entries are cleaned up lazily.
    """
    exp = _blacklist.get(jti)
    if exp is None:
        return False

    # If the blacklist entry itself has expired, remove it
    now = datetime.now(timezone.utc)
    if exp < now:
        # Optional: clean up expired entry
        _blacklist.pop(jti, None)
        return False

    return True
