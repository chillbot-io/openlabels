"""Detector plugin registry with decorator-based registration.

Detectors register themselves via the ``@register_detector`` class decorator.
The orchestrator discovers them at runtime instead of maintaining hardcoded
imports, so adding a new detector only requires defining the class — no
orchestrator changes needed.

Usage::

    from openlabels.core.detectors.registry import register_detector

    @register_detector
    class MyDetector(BaseDetector):
        name = "my_detector"
        ...

    # At runtime:
    from openlabels.core.detectors.registry import get_registered_detectors
    detectors = get_registered_detectors()  # {"my_detector": MyDetector, ...}
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Dict, List, Type

if TYPE_CHECKING:
    from .base import BaseDetector

logger = logging.getLogger(__name__)

_REGISTRY: Dict[str, Type[BaseDetector]] = {}


def register_detector(cls: Type[BaseDetector]) -> Type[BaseDetector]:
    """Class decorator that registers a detector by its ``name`` attribute.

    Raises ``ValueError`` if *name* is missing, still ``"base"``, or already
    taken by another class.
    """
    name = getattr(cls, "name", None)
    if not name or name == "base":
        raise ValueError(
            f"Detector {cls.__name__} must define a unique 'name' class attribute"
        )
    if name in _REGISTRY:
        raise ValueError(
            f"Detector name {name!r} already registered by {_REGISTRY[name].__name__}"
        )
    _REGISTRY[name] = cls
    return cls


def get_registered_detectors() -> Dict[str, Type[BaseDetector]]:
    """Return a snapshot of all registered detector classes."""
    return dict(_REGISTRY)


def get_detector_names() -> List[str]:
    """Return the names of all registered detectors."""
    return list(_REGISTRY.keys())


def create_detector(name: str, **kwargs: object) -> BaseDetector:
    """Instantiate a registered detector by *name*.

    Raises ``KeyError`` if the name is unknown.
    """
    if name not in _REGISTRY:
        raise KeyError(
            f"Unknown detector: {name!r}. Available: {list(_REGISTRY.keys())}"
        )
    return _REGISTRY[name](**kwargs)


def create_all_detectors(**kwargs: object) -> List[BaseDetector]:
    """Instantiate every registered detector that reports ``is_available()``."""
    detectors: list[BaseDetector] = []
    for name, cls in _REGISTRY.items():
        try:
            detector = cls(**kwargs)
            if detector.is_available():
                detectors.append(detector)
        except Exception as exc:
            logger.warning("Failed to create detector %s: %s", name, exc)
    return detectors
