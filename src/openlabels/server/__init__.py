"""OpenLabels Server - FastAPI-based API server."""


def __getattr__(name: str):
    """Lazy import to avoid loading heavy dependencies when only models are needed."""
    if name == "app":
        from openlabels.server.app import app
        return app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["app"]
