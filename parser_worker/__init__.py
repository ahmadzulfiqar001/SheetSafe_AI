"""Future isolated worker internals, exercised ONLY with synthetic unit fixtures.

No enabled CLI/HTTP/production dispatch or upload adapter. The fixed image
entrypoint exits 78 until a transport is separately approved. Python imports are not an
isolation boundary; FastAPI/Streamlit must never import these parser modules.
"""
