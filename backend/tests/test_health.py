from app.core.config import settings

def test_health_endpoint(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "malbox-ai"
    assert data["live_mode_enabled"] is True
    assert data["default_backend"] == "cape"
    assert "ready_for_analysis" in data
    assert "cape_reachable" in data
    assert "guest_vm_ready" in data
    assert "network_isolation_verified" in data
    assert "ghidra_installed" in data
    assert "rules_loaded" in data


def test_readiness_endpoint(client):
    response = client.get("/api/v1/readiness")
    assert response.status_code == 200
    data = response.json()
    assert "ready_for_analysis" in data
    assert "live_mode_configured" in data
    assert "operator_auth_configured" in data
    assert "status" in data


def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["documentation"] == "/docs"
