import re
import base64
from pathlib import Path
from typing import List

import io

def extract_base64_images(html_text: str) -> List[bytes]:
    # Match data:image/...;base64,<data> inside quotes
    pattern = re.compile(r"data:image\/[^;]+;base64,([A-Za-z0-9+\/=]+)")
    return [base64.b64decode(m) for m in pattern.findall(html_text)]


def save_images(datas: List[bytes], out_dir: Path) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: List[Path] = []
    for i, data in enumerate(datas, 1):
        p = out_dir / f"img{i}.png"
        p.write_bytes(data)
        paths.append(p)
    return paths

def build_variants(image_paths: List[Path], out_dir: Path) -> List[Path]:
    from PIL import Image, ImageOps, ImageFilter
    import numpy as np

    out_dir.mkdir(parents=True, exist_ok=True)

    imgs = [Image.open(p).convert("L") for p in image_paths]
    arrs = [np.array(im, dtype=np.uint8) for im in imgs]

    variants: List[Image.Image] = []

    # Individual denoise/threshold per image
    for idx, im in enumerate(imgs, 1):
        v = im.filter(ImageFilter.MedianFilter(size=3))
        variants.append(v)
        variants.append(ImageOps.invert(v))
        variants.append(v.point(lambda x: 255 if x > 128 else 0))

    # Combine across images
    stack = np.stack(arrs, axis=0)
    variants.append(Image.fromarray(np.median(stack, axis=0).astype(np.uint8)))
    variants.append(Image.fromarray(np.max(stack, axis=0).astype(np.uint8)))
    variants.append(Image.fromarray(np.min(stack, axis=0).astype(np.uint8)))

    # XOR and differences to surface hidden patterns
    xor_all = arrs[0]
    for a in arrs[1:]:
        xor_all = np.bitwise_xor(xor_all, a)
    variants.append(Image.fromarray(xor_all))

    mean = np.mean(stack, axis=0)
    std = np.std(stack, axis=0)
    diff = np.abs(stack - mean)
    diff_sum = diff.sum(axis=0)
    # Normalize to 0..255
    def norm(x):
        x = x - x.min()
        d = x.max() - x.min()
        return (255*(x/d if d != 0 else x)).astype(np.uint8)
    variants.append(Image.fromarray(norm(std)))
    variants.append(Image.fromarray(norm(diff_sum)))

    # More transforms on combined images: resize, adaptive threshold-like via mean
    def add_scaled(img: Image.Image):
        for scale in (1.5, 2.0, 3.0):
            w, h = img.size
            variants.append(img.resize((int(w*scale), int(h*scale)), Image.NEAREST))

    base_len = len(variants)
    for i in range(base_len):
        add_scaled(variants[i])

    # Save variants
    variant_paths: List[Path] = []
    for i, v in enumerate(variants, 1):
        p = out_dir / f"var_{i:02d}.png"
        v.save(p)
        variant_paths.append(p)
    return variant_paths


def try_decode(paths: List[Path]) -> None:
    try:
        import cv2  # type: ignore
    except Exception as e:
        print("OpenCV not available, skipping auto-decode:", e)
        return

    detector = cv2.QRCodeDetector()
    for p in paths:
        img = cv2.imread(str(p))
        if img is None:
            continue
        # try a few preprocess pipelines per image
        tries = [img]
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        tries.append(cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_NEAREST))
        tries.append(cv2.cvtColor(cv2.medianBlur(gray, 3), cv2.COLOR_GRAY2BGR))
        thr = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_MEAN_C, cv2.THRESH_BINARY, 31, 5)
        tries.append(cv2.cvtColor(thr, cv2.COLOR_GRAY2BGR))
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (3,3))
        tries.append(cv2.morphologyEx(cv2.cvtColor(thr, cv2.COLOR_GRAY2BGR), cv2.MORPH_OPEN, kernel))
        found = False
        for t in tries:
            data, points, _ = detector.detectAndDecode(t)
            if data:
                print(f"DECODED from {p.name}: {data}")
                found = True
                break
        if not found:
            data, points, _ = detector.detectAndDecode(img)
        if data:
            print(f"DECODED from {p.name}: {data}")


def main() -> None:
    root = Path(__file__).parent
    html = (root / "index.html").read_text(encoding="utf-8")
    datas = extract_base64_images(html)
    print(f"Found {len(datas)} embedded images")
    img_dir = root / "out"
    images = save_images(datas, img_dir)
    print("Saved:", ", ".join(p.name for p in images))

    var_dir = root / "out" / "variants"
    variants = build_variants(images, var_dir)
    print(f"Generated {len(variants)} variants in {var_dir}")

    try_decode(images + variants)


if __name__ == "__main__":
    main()


