# Quick Write-up (S3.jpg)

- Find hint via strings/EXIF: tokens P1, P2, P3 → combine uppercase, hyphen-separated.
- Carve appended ZIP from JPEG by locating `PK\x03\x04` and saving tail bytes.
- ZIP uses AES-256; extract with 7-Zip using password `WATPHO-RECLINING-BUDDHA`.
- Read `flag.txt`.

## Flag

```text
CSG_FLAG{Y0u-Are-Found-Hidd3n-Fi1e}
```