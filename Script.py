import os
import time
import json
import shutil
import requests
import subprocess
from pathlib import Path



# ==========================================================
# CONFIGURATION
# ==========================================================

BASE_URL = "http://localhost:8000"

ZIP_FOLDER = "Zip_Files"
APK_FOLDER = "APK_Test"
REPORT_FOLDER = "Reports"
SCANNED_FOLDER = "Scanned"
ARCHIVE_FOLDER = "Archive"

ZIP_PASSWORD = b"infected"
POLL_INTERVAL = 5

# Create folders if they don't exist
for folder in [
    ZIP_FOLDER,
    APK_FOLDER,
    REPORT_FOLDER,
    SCANNED_FOLDER,
    ARCHIVE_FOLDER,
]:
    os.makedirs(folder, exist_ok=True)


# ==========================================================
# EXTRACT ZIP FILES
# ==========================================================

def extract_zip_files():
    zip_files = list(Path(ZIP_FOLDER).glob("*.zip"))

    if not zip_files:
        print("No ZIP files found.")
        return

    for zip_file in zip_files:
        print(f"\nExtracting: {zip_file.name}")

        try:
            command = [
                "7z",
                "x",
                str(zip_file),
                f"-o{APK_FOLDER}",
                "-pinfected",
                "-y"
            ]

            result = subprocess.run(
                command,
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                print("Extraction failed!")
                print(result.stderr)
                continue

            print(f"Extracted: {zip_file.name}")

            shutil.move(
                str(zip_file),
                Path(ARCHIVE_FOLDER) / zip_file.name
            )

        except Exception as e:
            print(f"Failed to extract {zip_file.name}")
            print(e)


# ==========================================================
# FIND APK FILES
# ==========================================================

def find_apks():
    return list(Path(APK_FOLDER).rglob("*.apk"))


# ==========================================================
# UPLOAD APK
# ==========================================================

def upload_apk(apk_path):
    print(f"\nUploading: {apk_path.name}")

    with open(apk_path, "rb") as f:
        response = requests.post(
            f"{BASE_URL}/analyze",
            files={
                "file": (
                    apk_path.name,
                    f,
                    "application/vnd.android.package-archive",
                )
            },
        )

    response.raise_for_status()

    return response.json()["job_id"]


# ==========================================================
# WAIT FOR SCAN
# ==========================================================

def wait_for_scan(job_id):
    while True:

        response = requests.get(
            f"{BASE_URL}/status/{job_id}"
        )

        response.raise_for_status()

        status = response.json()

        progress = status.get("progress", 0)
        state = status.get("status", "Running")

        print(f"Progress: {progress}% | {state}")

        if progress >= 100 or state.lower() == "completed":
            break

        time.sleep(POLL_INTERVAL)


# ==========================================================
# DOWNLOAD REPORTS
# ==========================================================

def download_reports(job_id, apk_name):

    report_dir = Path(REPORT_FOLDER) / apk_name
    report_dir.mkdir(parents=True, exist_ok=True)

    # JSON Report
    response = requests.get(
        f"{BASE_URL}/report/{job_id}"
    )

    response.raise_for_status()

    with open(
        report_dir / "report.json",
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            response.json(),
            f,
            indent=4,
        )

    # PDF Report
    pdf = requests.get(
        f"{BASE_URL}/report/{job_id}/pdf"
    )

    if pdf.status_code == 200:

        with open(
            report_dir / "report.pdf",
            "wb",
        ) as f:

            f.write(pdf.content)


# ==========================================================
# SCAN APK
# ==========================================================

def scan_apk(apk_path):

    try:

        start = time.time()

        job_id = upload_apk(apk_path)

        wait_for_scan(job_id)

        download_reports(job_id, apk_path.stem)

        elapsed = round(
            time.time() - start,
            2,
        )

        print(
            f"Completed {apk_path.name} "
            f"in {elapsed} seconds."
        )

        shutil.move(
            str(apk_path),
            Path(SCANNED_FOLDER) / apk_path.name,
        )

    except Exception as e:

        print(f"Failed: {apk_path.name}")

        print(e)


# ==========================================================
# MAIN
# ==========================================================

def main():

    print("=" * 60)
    print("DROIDSCAN AUTOMATED BATCH SCANNER")
    print("=" * 60)

    # Step 1
    extract_zip_files()

    # Step 2
    apk_files = find_apks()

    if not apk_files:
        print("\nNo APK files found.")
        return

    total = len(apk_files)

    print(f"\nFound {total} APK(s).\n")

    # Step 3
    for index, apk in enumerate(apk_files, start=1):

        print("=" * 60)
        print(f"[{index}/{total}] {apk.name}")
        print("=" * 60)

        scan_apk(apk)

    print("\n")
    print("=" * 60)
    print("ALL SCANS COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()
