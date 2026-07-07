"""Bounded Phase 19A support utilities.

This package is intentionally explicit-use only. It is not imported by
``main.py`` and does not attach itself to canonical traversal startup.
"""

from sbp_lex.phase19a.pre_context_translator import (
    TranslationResult,
    translate_external_pre_context_package,
)

__all__ = ["TranslationResult", "translate_external_pre_context_package"]
