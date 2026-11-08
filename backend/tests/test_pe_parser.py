from app.services.submission.pe_parser import calculate_shannon_entropy, parse_pe_metadata

def test_entropy_empty():
    assert calculate_shannon_entropy(b"") == 0.0

def test_entropy_uniform():
    # 256 bytes with all byte values 0..255 has maximal entropy = 8.0
    data = bytes(range(256))
    entropy = calculate_shannon_entropy(data)
    assert 7.99 <= entropy <= 8.0

def test_entropy_low():
    # Repeated bytes have low entropy
    data = b"A" * 1000
    entropy = calculate_shannon_entropy(data)
    assert entropy == 0.0

def test_parse_non_pe():
    data = b"This is a plain text file, not a portable executable binary."
    meta = parse_pe_metadata(data)
    assert meta["is_valid_pe"] is False
    assert "Missing MZ header" in meta["warning"]

def test_parse_corrupted_pe():
    data = b"MZ" + b"\x00" * 100
    meta = parse_pe_metadata(data)
    assert meta["is_valid_pe"] is False
    assert meta["warning"] is not None
