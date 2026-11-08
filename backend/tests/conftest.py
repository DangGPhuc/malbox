import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.core.database import Base, get_db
import app.main as app_main
from app.main import app

# StaticPool ensures the in-memory SQLite database remains open across connections
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

@pytest.fixture(scope="session", autouse=True)
def setup_test_env(tmp_path_factory):
    """Sets up temporary quarantine and data paths for testing."""
    test_dir = tmp_path_factory.mktemp("malbox_test_data")
    settings.DATA_DIR = test_dir
    settings.QUARANTINE_DIR = test_dir / "quarantine"
    settings.ARTIFACTS_DIR = test_dir / "artifacts"
    settings.setup_directories()

@pytest.fixture(scope="function")
def db_session():
    """Provides a fresh database session for each test function."""
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)

@pytest.fixture(scope="function")
def client(db_session, monkeypatch):
    """Provides a FastAPI TestClient with overridden database dependency and mock init_db."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    # Prevent lifespan from touching production DB during tests
    monkeypatch.setattr(app_main, "init_db", lambda: None)
    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
