"""VGen Gateway v1 control plane."""

from .database import GatewayDatabase

__all__ = ["GatewayDatabase", "create_app"]


def __getattr__(name: str):  # type: ignore[no-untyped-def]
    # Keep lightweight commands such as `vgen-gateway --help` free of database
    # and bootstrap side effects. FastAPI is imported only when an app is asked for.
    if name == "create_app":
        from .app import create_app

        return create_app
    raise AttributeError(name)
