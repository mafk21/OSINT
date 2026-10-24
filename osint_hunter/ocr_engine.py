"""Local Multi-Backend Screenshot OCR & QR/Barcode Extractor (Upgrade #3).

100% Local OPSEC — ZERO cloud uploads.
Extracts visible handles, phone numbers, URLs, emails, IBANs, and Arabic/English text
from dropped screenshots, chat captures, flyers, and photos using the best local engine
available on the host machine:
  1. `tesseract` CLI (`eng+ara` when Arabic tessdata is installed, else `eng`)
  2. macOS Native Vision Framework (`VNRecognizeTextRequest` via `/usr/bin/swift` — built into macOS)
  3. Windows 10/11 Native WinRT OCR (`Windows.Media.Ocr.OcrEngine` via `powershell`)
  4. Optional Python OCR libraries (`rapidocr_onnxruntime`, `pytesseract`) if installed
  5. Optional `zbarimg` CLI for QR codes / WhatsApp QR / barcodes inside screenshots
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ARABIC_INDIC_TRANS = str.maketrans(
    "٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹",
    "01234567890123456789",
)

SPACED_IBAN_RE = re.compile(
    r"\b([A-Z]{2}\d{2}(?:\s+[A-Z0-9]{4}){3,7}(?:\s+[A-Z0-9]{1,4})?)\b"
)
LOCAL_SA_MOBILE_RE = re.compile(
    r"(?<!\d)0(5\d[\s.-]?\d{3}[\s.-]?\d{4})(?!\d)"
)


def normalize_ocr_text_for_osint(raw_text: str) -> str:
    """Clean common OCR spacing/numeral artifacts so OSINT selector regexes match reliably."""
    if not raw_text:
        return ""
    # 1. Convert Eastern-Arabic & Persian digits to ASCII digits
    s = raw_text.translate(ARABIC_INDIC_TRANS)

    # 1b. De-obfuscate defanged / OCR-spaced emails & domains (e.g. "ceo [at] acme [dot] sa")
    s = re.sub(r"\s*[\[\(]\s*at\s*[\]\)]\s*", "@", s, flags=re.IGNORECASE)
    s = re.sub(r"\s*[\[\(]\s*dot\s*[\]\)]\s*", ".", s, flags=re.IGNORECASE)

    # 2. Rejoin spaced @handles (e.g. "@ dr.abo3tab" -> "@dr.abo3tab")
    s = re.sub(r"@\s+([A-Za-z0-9_][A-Za-z0-9_.-]{2,38})\b", r"@\1", s)

    # 3. Rejoin spaced social profile paths (e.g. "instagram.com / user" -> "https://instagram.com/user")
    s = re.sub(
        r"\b((?:instagram\.com|tiktok\.com|snapchat\.com/add|x\.com|twitter\.com|t\.me|linktr\.ee|wa\.me))\s*/\s*(@?[A-Za-z0-9_.-]{2,38})",
        r"https://\1/\2",
        s,
        flags=re.IGNORECASE,
    )

    # 4. Compact spaced IBANs (e.g. "SA03 8000 0000 6080 1016 7519" -> append compact SA038000...)
    extras: list[str] = []
    for m in SPACED_IBAN_RE.finditer(s):
        compact = re.sub(r"\s+", "", m.group(1))
        if 15 <= len(compact) <= 34:
            extras.append(compact)

    # 5. Expand Saudi local 05XXXXXXXX mobile numbers found in screenshots to +9665XXXXXXXX
    for m in LOCAL_SA_MOBILE_RE.finditer(s):
        digs = re.sub(r"\D", "", m.group(1))
        if len(digs) == 9 and digs.startswith("5"):
            extras.append(f"+966{digs}")

    if extras:
        s = s + "\n" + "\n".join(dict.fromkeys(extras))
    return s.strip()


def get_ocr_backend_status() -> dict[str, Any]:
    """Report which local offline OCR & QR engines are available on this OS."""
    tess = shutil.which("tesseract")
    zbar = shutil.which("zbarimg")
    mac_swift = "/usr/bin/swift" if (sys.platform == "darwin" and Path("/usr/bin/swift").is_file()) else None
    win_ps = shutil.which("powershell") if sys.platform == "win32" else None

    py_rapid = False
    try:
        import rapidocr_onnxruntime  # type: ignore  # noqa: F401
        py_rapid = True
    except Exception:
        pass

    backends: list[str] = []
    if tess:
        backends.append("tesseract_cli")
    if py_rapid:
        backends.append("rapidocr_onnx")
    if mac_swift:
        backends.append("macos_vision_native")
    if win_ps:
        backends.append("windows_winrt_ocr")

    return {
        "ocr_available": bool(backends),
        "preferred_backend": backends[0] if backends else None,
        "available_backends": backends,
        "qr_zbar_available": bool(zbar),
    }


def _ocr_via_tesseract(img_path: Path) -> str:
    tess = shutil.which("tesseract")
    if not tess:
        return ""
    lang = "eng"
    try:
        lp = subprocess.run([tess, "--list-langs"], capture_output=True, text=True, timeout=2.5)
        if "ara" in (lp.stdout or "") + (lp.stderr or ""):
            lang = "eng+ara"
    except Exception:
        pass
    try:
        proc = subprocess.run(
            [tess, str(img_path), "stdout", "--oem", "1", "-l", lang],
            capture_output=True,
            text=True,
            timeout=6.0,
        )
        if proc.returncode == 0 and proc.stdout:
            return proc.stdout.strip()
    except Exception:
        pass
    return ""


def _ocr_via_macos_vision(img_path: Path) -> str:
    if sys.platform != "darwin" or not Path("/usr/bin/swift").is_file():
        return ""
    swift_code = (
        "import Foundation\nimport Vision\nimport AppKit\n"
        "let u = URL(fileURLWithPath: CommandLine.arguments[1])\n"
        "guard let img = NSImage(contentsOf: u), let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil) else { exit(0) }\n"
        "let req = VNRecognizeTextRequest()\n"
        "req.recognitionLevel = .accurate\n"
        "req.usesLanguageCorrection = false\n"
        "req.recognitionLanguages = [\"en-US\", \"ar-SA\"]\n"
        "try? VNImageRequestHandler(cgImage: cg, options: [:]).perform([req])\n"
        "for o in (req.results ?? []) { if let c = o.topCandidates(1).first { print(c.string) } }\n"
    )
    try:
        proc = subprocess.run(
            ["/usr/bin/swift", "-e", swift_code, str(img_path)],
            capture_output=True,
            text=True,
            timeout=8.0,
        )
        if proc.returncode == 0 and proc.stdout:
            return proc.stdout.strip()
    except Exception:
        pass
    return ""


def _ocr_via_windows_winrt(img_path: Path) -> str:
    if sys.platform != "win32":
        return ""
    ps = shutil.which("powershell")
    if not ps:
        return ""
    ps_script = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "Add-Type -AssemblyName System.Runtime.WindowsRuntime; "
        "$null = [Windows.Storage.StorageFile,Windows.Storage,ContentType=WindowsRuntime]; "
        "$null = [Windows.Graphics.Imaging.BitmapDecoder,Windows.Graphics,ContentType=WindowsRuntime]; "
        "$null = [Windows.Media.Ocr.OcrEngine,Windows.Foundation,ContentType=WindowsRuntime]; "
        "$asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]; "
        "Function Await($op, $t) { $m = $asTask.MakeGenericMethod($t); $tk = $m.Invoke($null, @($op)); $tk.Wait(-1) | Out-Null; $tk.Result } "
        f"$f = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync('{str(img_path).replace(chr(39), chr(39)*2)}')) ([Windows.Storage.StorageFile]); "
        "$st = Await ($f.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream]); "
        "$dec = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($st)) ([Windows.Graphics.Imaging.BitmapDecoder]); "
        "$bmp = Await ($dec.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap]); "
        "$eng = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages(); "
        "$res = Await ($eng.RecognizeAsync($bmp)) ([Windows.Media.Ocr.OcrResult]); "
        "Write-Output $res.Text"
    )
    try:
        proc = subprocess.run(
            [ps, "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=8.0,
        )
        if proc.returncode == 0 and proc.stdout:
            return proc.stdout.strip()
    except Exception:
        pass
    return ""


def _ocr_via_rapidocr(img_path: Path) -> str:
    try:
        from rapidocr_onnxruntime import RapidOCR  # type: ignore

        engine = RapidOCR()
        result, _ = engine(str(img_path))
        if result:
            return "\n".join(str(row[1]) for row in result if len(row) >= 2 and row[1])
    except Exception:
        pass
    return ""


def _scan_qr_codes(img_path: Path) -> list[str]:
    zbar = shutil.which("zbarimg")
    if not zbar:
        return []
    try:
        proc = subprocess.run(
            [zbar, "--quiet", "--raw", str(img_path)],
            capture_output=True,
            text=True,
            timeout=4.0,
        )
        if proc.returncode == 0 and proc.stdout:
            return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    except Exception:
        pass
    return []


def extract_text_and_codes_from_image(image_path: str | Path) -> dict[str, Any]:
    """Run local QR/barcode scan + local OCR on an image file and normalize OSINT selectors."""
    p = Path(image_path)
    if not p.is_file():
        return {"ocr_available": False, "backend_used": None, "raw_text": "", "normalized_text": "", "qr_or_barcodes": [], "line_count": 0}

    status = get_ocr_backend_status()
    qr_codes = _scan_qr_codes(p)

    raw_txt = ""
    used = None
    for backend_name, fn in (
        ("tesseract_cli", _ocr_via_tesseract),
        ("rapidocr_onnx", _ocr_via_rapidocr),
        ("macos_vision_native", _ocr_via_macos_vision),
        ("windows_winrt_ocr", _ocr_via_windows_winrt),
    ):
        if backend_name in status["available_backends"]:
            raw_txt = fn(p)
            if raw_txt:
                used = backend_name
                break
            if used is None:
                used = backend_name

    norm_txt = normalize_ocr_text_for_osint(raw_txt)
    lines = [ln.strip() for ln in norm_txt.splitlines() if ln.strip()]
    return {
        "ocr_available": status["ocr_available"],
        "backend_used": used,
        "raw_text": raw_txt[:12_000],
        "normalized_text": norm_txt[:12_000],
        "qr_or_barcodes": qr_codes[:10],
        "line_count": len(lines),
    }
