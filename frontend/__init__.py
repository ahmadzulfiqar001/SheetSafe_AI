"""Streamlit frontend package for SheetSafe AI.

Communicates exclusively with the FastAPI control plane over bounded HTTP calls.
Never imports backend database, private storage, parser worker, or Docker modules.
"""
