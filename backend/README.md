# malbox-ai Backend

FastAPI backend service powering the **malbox-ai** AI-Driven Dynamic Malware Analysis and Behavioral Intelligence Platform.

## Components
- `app/api/`: REST API version 1 routers
- `app/core/`: Configuration, database engines, security primitives
- `app/models/`: SQLAlchemy 2.0 ORM schemas
- `app/schemas/`: Pydantic v2 data transfer models
- `app/services/`: PE parser, AI orchestrator, sandbox backends (Replay and CAPE), normalizer, correlator, graph builder, detection engine, and reporter
- `app/workers/`: Persistent bounded pipeline task worker

## Installation
```bash
python -m pip install -e ".[dev]"
```
