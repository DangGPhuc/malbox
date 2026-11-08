import io
from app.models.analysis import AnalysisStatus

def test_upload_sample_deduplication(client):
    file_content = b"MZ" + b"\x90" * 200 + b"FAKE_PE_HEADER_PAYLOAD"
    file_tuple = ("test_sample.exe", io.BytesIO(file_content), "application/octet-stream")

    # First upload
    res1 = client.post("/api/v1/samples", files={"file": file_tuple})
    assert res1.status_code == 201
    sample1 = res1.json()
    assert sample1["sha256"] is not None
    assert sample1["file_name"] == "test_sample.exe"

    # Second upload with same content -> should deduplicate
    file_tuple2 = ("test_sample_copy.exe", io.BytesIO(file_content), "application/octet-stream")
    res2 = client.post("/api/v1/samples", files={"file": file_tuple2})
    assert res2.status_code == 201
    sample2 = res2.json()
    assert sample2["id"] == sample1["id"]
    assert sample2["sha256"] == sample1["sha256"]

def test_live_mode_safety_gate(client):
    file_content = b"MZ_TEST_SAMPLE"
    res = client.post("/api/v1/samples", files={"file": ("malware.exe", io.BytesIO(file_content))})
    sample = res.json()

    # Attempt to start an analysis with live_mode=True
    analysis_payload = {
        "sample_id": sample["id"],
        "backend_type": "cape",
        "live_mode": True,
        "approved_by_user": True,
    }
    res_analysis = client.post("/api/v1/analyses", json=analysis_payload)
    # Must be blocked by safety policy (403 Forbidden)
    assert res_analysis.status_code == 403
    assert "disabled by server security policy" in res_analysis.json()["detail"]

def test_create_and_retrieve_analysis(client):
    file_content = b"MZ_SAMPLE_REPLAY"
    res = client.post("/api/v1/samples", files={"file": ("replay_sample.exe", io.BytesIO(file_content))})
    sample = res.json()

    # Create standard replay analysis
    analysis_payload = {
        "sample_id": sample["id"],
        "backend_type": "replay",
        "profile": "standard",
        "live_mode": False,
        "timeout_seconds": 60,
    }
    res_analysis = client.post("/api/v1/analyses", json=analysis_payload)
    assert res_analysis.status_code == 201
    analysis = res_analysis.json()
    assert analysis["status"] == AnalysisStatus.PREFLIGHT.value
    assert analysis["backend_type"] == "replay"

    # Retrieve analysis by ID
    get_res = client.get(f"/api/v1/analyses/{analysis['id']}")
    assert get_res.status_code == 200
    detail = get_res.json()
    assert detail["id"] == analysis["id"]
    assert detail["sample_id"] == sample["id"]
    assert detail["sample_file_name"] == "replay_sample.exe"

