#!/usr/bin/env python
"""Run the ScrubIQ API server."""

import uvicorn


def main():
    """Start the API server."""
    uvicorn.run(
        "scrubiq.api.app:app",
        host="127.0.0.1",
        port=8741,
        reload=True,
        log_level="info",
    )


if __name__ == "__main__":
    main()
