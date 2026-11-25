#!/usr/bin/env python3
"""
Extract Linux IKCFG_ST .config and decode FDT metadata from a prebuilt Image.gz-dtb / DTB.
Author: Riajul (Riajul18-19)
"""
import argparse
import pathlib
import re
import struct
import zlib


def extract_kernel_config(kernel_path: pathlib.Path, out_path: pathlib.Path | None) -> None:
    raw = kernel_path.read_bytes()
    decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
    image = decomp.decompress(raw)
    print(f"[*] Kernel image size (compressed): {len(raw):,} bytes")
    print(f"[*] Kernel Image size (decompressed): {len(image):,} bytes (appended DTB tail: {len(decomp.unused_data):,} bytes)")

    for m in re.findall(b"Linux version [^\n\x00]{10,200}", image)[:2]:
        print(f"[*] Banner: {m.decode('utf-8', 'ignore')}")

    marker = b"IKCFG_ST"
    idx = image.find(marker)
    if idx == -1:
        raise RuntimeError("IKCFG_ST marker not found inside decompressed kernel Image")

    cfg_stream = zlib.decompressobj(16 + zlib.MAX_WBITS)
    cfg_text = cfg_stream.decompress(image[idx + len(marker):]).decode("utf-8", "ignore")
    lines = cfg_text.splitlines()
    print(f"[*] Extracted IKCFG_ST config entries: {len(lines)}")
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"[*] Wrote extracted config to {out_path}")


def dump_fdt_summary(dtb_path: pathlib.Path) -> None:
    data = dtb_path.read_bytes()
    magic, totalsize, _, _, _, version = struct.unpack(">6I", data[:24])
    if magic != 0xD00DFEED:
        raise ValueError(f"Invalid FDT magic in {dtb_path}: 0x{magic:08x}")
    compats = sorted(set(m.decode("utf-8", "ignore") for m in re.findall(b"qcom,[a-zA-Z0-9._-]+", data)))
    print(f"[*] DTB {dtb_path.name}: magic=0x{magic:08x}, size={totalsize:,} bytes, version={version}")
    print(f"    Compatible strings ({len(compats)}): {', '.join(compats[:15])}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect MSM8953 prebuilt kernel Image.gz-dtb and DTB blobs")
    parser.add_argument("--kernel", type=pathlib.Path, required=True, help="Path to Image.gz-dtb")
    parser.add_argument("--dtb", type=pathlib.Path, help="Optional path to standalone .dtb file")
    parser.add_argument("--out", type=pathlib.Path, help="Optional output path for extracted defconfig")
    args = parser.parse_args()

    extract_kernel_config(args.kernel, args.out)
    if args.dtb:
        dump_fdt_summary(args.dtb)


if __name__ == "__main__":
    main()
