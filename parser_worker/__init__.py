"""Future isolated worker internals, exercised ONLY with synthetic unit fixtures.

No CLI/HTTP/production dispatch or upload adapter. Python imports are not an
isolation boundary; FastAPI/Streamlit must never import these parser modules.
"""
