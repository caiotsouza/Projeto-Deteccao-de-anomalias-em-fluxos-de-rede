"""Ponto de entrada ASGI para Uvicorn e Docker."""

from src.dashboard_api import create_app


app = create_app()
