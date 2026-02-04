"""
Server, worker, and GUI commands.
"""

import click


@click.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to (use 0.0.0.0 for all interfaces)")
@click.option("--port", default=8000, type=int, help="Port to bind to")
@click.option("--workers", default=4, type=int, help="Number of worker processes")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
def serve(host: str, port: int, workers: int, reload: bool):
    """Start the OpenLabels API server."""
    import uvicorn

    uvicorn.run(
        "openlabels.server.app:app",
        host=host,
        port=port,
        workers=1 if reload else workers,
        reload=reload,
    )


@click.command()
@click.option("--concurrency", default=None, type=int, help="Number of concurrent jobs")
def worker(concurrency: int):
    """Start a worker process for job execution."""
    from openlabels.jobs.worker import run_worker

    run_worker(concurrency=concurrency)


@click.command()
@click.option("--server", default="http://localhost:8000", help="Server URL to connect to")
def gui(server: str):
    """Launch the OpenLabels GUI application."""
    from openlabels.gui.main import run_gui

    run_gui(server_url=server)
