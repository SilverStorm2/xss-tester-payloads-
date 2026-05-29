# XSS Lab

Lokalne laboratorium do **ręcznego testowania payloadów XSS** (Cross-Site Scripting). Aplikacja symuluje typowe scenariusze podatności — bez wysyłania żądań na zewnętrzne serwisy — żebyś mógł bezpiecznie sprawdzić, jak payload zachowuje się w przeglądarce.

> **Tylko do autoryzowanych testów:** używaj na własnych aplikacjach lub za pisemną zgodą (pentest, bug bounty, środowisko testowe). Nie testuj obcych systemów bez pozwolenia.

## Co robi aplikacja

### Ręczny tester
- Wklejasz payload w pole tekstowe (np. komentarz, bio, ticket).
- Wybierasz tryb renderowania: `innerHTML` (podatne), `textContent` (bezpieczne) lub escapowanie HTML.
- Widzisz podgląd na żywo, wygenerowane źródło HTML oraz symulację kontekstu atrybutu.
- Gotowe presety: marker tekstowy, `img onerror`, `svg onload`, `script`, breakout atrybutu.
- Każda sesja ma unikalny **marker** (`XSS-STORED-POC-…`) — ułatwia potwierdzenie wykonania payloadu w dzienniku.

### Stored XSS (symulacja)
- Formularz zapisuje wpisy lokalnie (`localStorage`) — symulacja POST.
- Lista wpisów odzwierciedla odczyt z serwera (GET) w wybranym trybie renderowania.
- Przy podatnym `innerHTML` widać, czy zapisany payload wykonuje się po ponownym wyświetleniu.

### Skrypt Python (`stored_xss_poc.py`)
- Automatyczne wysłanie payloadu na wskazany URL i weryfikacja markera w odpowiedzi.
- Przydatny do testów stored XSS na prawdziwym backendzie (z autoryzacją).

## Uruchomienie

```bash
npm install
npm run dev
```

Aplikacja domyślnie startuje pod adresem `http://localhost:5173`.

Produkcja:

```bash
npm run build
npm run preview
```

## Przykład użycia skryptu Python

```bash
pip install requests

python3 stored_xss_poc.py \
  --submit-url "https://twoja-app.example/api/comments" \
  --field comment \
  --verify-url "https://twoja-app.example/comments" \
  --cookie "session=..." \
  --extra "post_id=1"
```

Opcje: `--csrf-field`, `--csrf-url`, `--payload-index` (0 = marker, 1 = img, 2 = svg), `--method GET|POST`.

## Stack

- [React](https://react.dev/) + [Vite](https://vite.dev/)
- Brak backendu — wszystko działa w przeglądarce (stored symulowany przez `localStorage`)

## Struktura

```
src/App.jsx       — interfejs labu (tester, stored, dziennik)
stored_xss_poc.py — automatyczny PoC stored XSS (CLI)
```
