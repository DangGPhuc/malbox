import os
import shutil
import subprocess
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
UI_SCREENSHOT_DIR = REPO_ROOT / "docs" / "ui" / "screenshots"
LEGACY_SCREENSHOT_DIR = REPO_ROOT / "docs" / "screenshots"
UI_SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
LEGACY_SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

ANALYSIS_ID = "f8ad1767-580f-449b-a290-6230cff8ba99"
BASE_URL = "http://127.0.0.1:5173"

PAGES = [
    ("01_dashboard", "#dashboard"),
    ("02_submit", "#submit"),
    ("03_workspace", f"#workspace/{ANALYSIS_ID}"),
    ("04_behavior_graph", f"#graph/{ANALYSIS_ID}"),
    ("05_static_explorer", f"#static/{ANALYSIS_ID}"),
    ("06_correlation_explorer", f"#correlation/{ANALYSIS_ID}"),
    ("07_intelligence_report", f"#report/{ANALYSIS_ID}"),
    ("08_malware_classification", f"#report/{ANALYSIS_ID}"),
]

VIEWPORTS = [
    ("desktop", 1440, 900),
    ("laptop", 1024, 768),
    ("mobile", 390, 844),
]

THEMES = ["light", "dark"]


def capture(url: str, output_path: Path, width: int, height: int):
    cmd = [
        "chromium",
        "--headless",
        "--no-sandbox",
        "--disable-gpu",
        f"--window-size={width},{height}",
        "--virtual-time-budget=4000",
        f"--screenshot={output_path}",
        url,
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        print(f"[OK] Saved {output_path.name} ({output_path.stat().st_size} bytes)")
        # Also copy to legacy screenshot directory
        shutil.copyfile(output_path, LEGACY_SCREENSHOT_DIR / output_path.name)
    else:
        print(f"[FAIL] {output_path.name}: {res.stderr.strip()}")


def main():
    print("Capturing forensic UI screenshots with headless Chromium...")

    # 1. Capture primary pages on desktop in light and dark
    for name, hash_route in PAGES:
        for theme in THEMES:
            url = f"{BASE_URL}/?theme={theme}{hash_route}"
            out_file = UI_SCREENSHOT_DIR / f"{name}_desktop_{theme}.png"
            capture(url, out_file, 1440, 900)

    # 2. Capture representative laptop viewports
    for name, hash_route in [PAGES[0], PAGES[1], PAGES[2], PAGES[6]]:
        url = f"{BASE_URL}/?theme=light{hash_route}"
        out_file = UI_SCREENSHOT_DIR / f"{name}_laptop_light.png"
        capture(url, out_file, 1024, 768)

    # 3. Capture representative mobile viewports
    for name, hash_route in [PAGES[0], PAGES[1], PAGES[2]]:
        url = f"{BASE_URL}/?theme=light{hash_route}"
        out_file = UI_SCREENSHOT_DIR / f"{name}_mobile_light.png"
        capture(url, out_file, 390, 844)

    print("\nVisual verification screenshots complete.")


if __name__ == "__main__":
    main()
