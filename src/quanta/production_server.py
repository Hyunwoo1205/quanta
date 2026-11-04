"""Tie a failed numerical supervisor to the host's single restart policy."""
from __future__ import annotations

import logging
import uvicorn


class ProductionServer(uvicorn.Server):
    """Uvicorn 0.54.0 owns HTTP shutdown; systemd owns process restart."""

    def __init__(self, app, *, port: int):
        self.quanta_app = app
        self.worker_failed = False
        super().__init__(uvicorn.Config(
            app, host="127.0.0.1", port=port, workers=1, reload=False,
            proxy_headers=False, forwarded_allow_ips="", access_log=False,
            server_header=False, log_level="warning", http="h11", ws="none",
            lifespan="on", limit_concurrency=32, backlog=32,
            timeout_keep_alive=5, timeout_graceful_shutdown=20,
        ))

    async def on_tick(self, counter: int) -> bool:
        # Keep normal signal-driven shutdown distinct from a worker failure.
        if await super().on_tick(counter):
            return True
        if self.started and self.quanta_app._started and not self.quanta_app.worker.healthy:
            self.worker_failed = True
            logging.getLogger("uvicorn.error").error("Numerical supervisor stopped; shutting down for host restart")
            return True
        return False


def run_production(app, *, port: int) -> int:
    server = ProductionServer(app, port=port)
    server.run()
    # Startup failure and a dead supervisor must trigger Restart=on-failure.
    return 2 if server.worker_failed or not server.started else 0
