"""Operator runner foundation; no Docker connection or execution on import.

FastAPI and Streamlit must not import a future runtime adapter or gain daemon
access. This package defines policy, a fixed fixture and an injectable stopped-
container lifecycle contract. No concrete Docker transport is supplied.
"""
