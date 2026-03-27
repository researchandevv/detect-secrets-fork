"""
Confidence-based filter for the detect-secrets scan pipeline.

Drops findings below a configurable confidence threshold during scanning.
This filter is OPT-IN ONLY — it is NOT included in the default filter set.
Users must explicitly add it to their baseline or settings to activate it.

Usage in .secrets.baseline 'filters_used':
    {
        "path": "detect_secrets.filters.confidence_filter.is_below_confidence_threshold",
        "min_confidence": 0.5
    }

Or for context-aware filtering (adjusts by file path):
    {
        "path": "detect_secrets.filters.confidence_filter.is_below_contextual_confidence_threshold",
        "min_confidence": 0.5
    }

Design rationale:
    The confidence module (detect_secrets.plugins.confidence) already provides
    get_confidence() and get_contextual_confidence(), but these are overlay
    functions — they score findings after scanning, not during. This filter
    wires confidence scoring into the scan pipeline via the standard filter
    interface, so low-confidence findings are dropped before reaching the
    baseline.

    This is opt-in to preserve backward compatibility: existing installations
    that upgrade will see no behavioral change. The filter only activates when
    explicitly configured.

Analogous to rapid-dismiss patterns in security scanning — findings with near-zero
true positive probability are dismissed without manual review. Here, findings with
confidence below threshold are dismissed without inclusion in the baseline.
"""
from functools import lru_cache
from typing import Optional

from ..plugins.base import BasePlugin
from ..settings import get_settings
from .util import get_caller_path


def is_below_confidence_threshold(
    secret: str,
    plugin: BasePlugin,
) -> bool:
    """Filter out findings from detectors below the confidence threshold.

    Uses type-only confidence scoring (detector type -> confidence score).

    Args:
        secret: The secret string (required by filter interface, not used
            for scoring — confidence is per-detector-type, not per-secret).
        plugin: The plugin that detected the secret.

    Returns:
        True if the finding should be filtered out (confidence below threshold).
        False if the finding should be kept.
    """
    from ..plugins.confidence import get_confidence

    min_confidence = _get_min_confidence()
    if min_confidence is None:
        # No threshold configured — do not filter anything
        return False

    secret_type = getattr(plugin, 'secret_type', None)
    if secret_type is None:
        # Unknown plugin type — cannot score, keep the finding
        return False

    confidence = get_confidence(secret_type)
    return confidence < min_confidence


def is_below_contextual_confidence_threshold(
    secret: str,
    plugin: BasePlugin,
    filename: str,
) -> bool:
    """Filter out findings using context-aware confidence scoring.

    Uses file-path-aware scoring which adjusts confidence based on whether
    the file is a test, lock file, vendor directory, etc.

    Args:
        secret: The secret string.
        plugin: The plugin that detected the secret.
        filename: The file path where the secret was found.

    Returns:
        True if the finding should be filtered out.
    """
    from ..plugins.confidence import get_contextual_confidence

    min_confidence = _get_contextual_min_confidence()
    if min_confidence is None:
        return False

    secret_type = getattr(plugin, 'secret_type', None)
    if secret_type is None:
        return False

    confidence = get_contextual_confidence(secret_type, filename)
    return confidence < min_confidence


@lru_cache(maxsize=1)
def _get_min_confidence() -> Optional[float]:
    """Read min_confidence from filter settings. Returns None if not configured."""
    path = get_caller_path(offset=1)
    try:
        config = get_settings().filters.get(path, {})
        value = config.get('min_confidence')
        if value is not None:
            return float(value)
    except (AttributeError, ValueError, TypeError):
        pass
    return None


@lru_cache(maxsize=1)
def _get_contextual_min_confidence() -> Optional[float]:
    """Read min_confidence for contextual filter. Returns None if not configured."""
    path = get_caller_path(offset=1)
    try:
        config = get_settings().filters.get(path, {})
        value = config.get('min_confidence')
        if value is not None:
            return float(value)
    except (AttributeError, ValueError, TypeError):
        pass
    return None
