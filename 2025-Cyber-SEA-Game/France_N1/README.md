# France N1

Given an `index.html`, examine it to find the flag.

## Solution

The HTML draws a 4-cell table where each cell's background is a base64-encoded PNG
(`.bg1`..`.bg4`). Each one alone looks like a noisy QR code.

`extract_decode.py`:

1. Extract the 4 base64 images out of the HTML (`data:image/...;base64,...`) and
   save them as `img1.png`..`img4.png`.
2. Generate variants to recover the QR: per-image denoise/threshold/invert, plus
   combinations across all four (median / min / max / XOR / std-dev), then a few
   upscales. One of these combinations resolves the share noise into a clean QR.
3. Auto-decode every variant with OpenCV's `QRCodeDetector`. The combined variants
   decode successfully.

```bash
uv run extract_decode.py
# Found 4 embedded images
# Saved: img1.png, img2.png, img3.png, img4.png
# DECODED from var_14.png: https://cyberseagame2025.s3.us-east-2.amazonaws.com/ltnytc9p84wy8pcw8y4tc.txt
```

The QR points to a text file hosted on S3, which held the flag.

## SSE-C bypass

Hitting the S3 URL directly does not work — the object is stored with **SSE-C**
(server-side encryption with a customer-provided AES-256 key) so a plain GET returns:

```
InvalidRequest: The object was stored using a form of Server Side Encryption.
The correct parameters must be provided to retrieve the object.
```

The intended bypass is to leverage the `fetch.php` proxy.

