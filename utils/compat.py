#!/usr/bin/env python3
"""
Maxima Utils: Colorama Compatibility Shim
colorama kurulu değilse boş string döndüren sahte sınıf kullanılır.
"""

try:
    from colorama import Fore, Back, Style, init as _init
    _init(autoreset=False)
except ImportError:
    class _NoColor:
        """colorama yoksa tüm renk attribute'ları boş string döndürür."""
        def __getattr__(self, name):
            return ""

    Fore  = _NoColor()
    Back  = _NoColor()
    Style = _NoColor()

__all__ = ["Fore", "Back", "Style"]
