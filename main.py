"""Vercel entrypoint: re-export the FastAPI app from the api package."""

from api.main import app

__all__ = ["app"]
