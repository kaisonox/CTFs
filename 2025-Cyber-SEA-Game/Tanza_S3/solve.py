import os
import shutil
import subprocess
from pathlib import Path

JPEG_NAME = "S3.jpg"
ZIP_NAME = "embedded.zip"
PASSWORD = b"WATPHO-RECLINING-BUDDHA"


def carve_zip_from_jpeg(jpeg_path: Path, out_zip: Path) -> None:
    data = jpeg_path.read_bytes()
    sig = b"PK\x03\x04"
    idx = data.find(sig)
    if idx == -1:
        raise RuntimeError("No ZIP signature found in JPEG")
    out_zip.write_bytes(data[idx:])


def extract_with_7z(zip_path: Path, out_dir: Path, password: bytes) -> None:
    sevenz = shutil.which("7z") or shutil.which("7z.exe")
    if not sevenz:
        raise RuntimeError("7-Zip not found in PATH. Install 7-Zip or add it to PATH.")
    cmd = [sevenz, "x", "-y", f"-p{password.decode()}", str(zip_path), f"-o{out_dir}"]
    subprocess.check_call(cmd, shell=False)


def main() -> None:
    base = Path(__file__).resolve().parent
    jpeg = base / JPEG_NAME
    out_zip = base / ZIP_NAME
    out_dir = base

    if not jpeg.exists():
        raise FileNotFoundError(jpeg)

    carve_zip_from_jpeg(jpeg, out_zip)
    extract_with_7z(out_zip, out_dir, PASSWORD)

    flag_file = base / "flag.txt"
    if flag_file.exists():
        print(flag_file.read_text().strip())
    else:
        print("Extraction done, but flag.txt not found.")


if __name__ == "__main__":
    main()
