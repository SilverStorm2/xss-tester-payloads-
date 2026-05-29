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

Produkcja lokalnie:

```bash
npm run build
npm run preview
```

## Wdrożenie na Vercel

Projekt jest gotowy pod [Vercel](https://vercel.com) (statyczna aplikacja Vite, katalog `dist`).

### Przez panel (Git)

1. Wypchnij repozytorium na GitHub / GitLab / Bitbucket.
2. W [vercel.com/new](https://vercel.com/new) zaimportuj repozytorium.
3. Vercel wykryje **Vite** — zostaw domyślne ustawienia (build: `npm run build`, output: `dist`).
4. Kliknij **Deploy**.

Plik `vercel.json` ustawia framework i przekierowania SPA (odświeżenie strony nie zwraca 404).

### Przez CLI

```bash
npm i -g vercel
vercel
```

Pierwsze uruchomienie przeprowadzi konfigurację projektu; `vercel --prod` wdroży na produkcję.

### Uwagi

- **Skrypt Python** (`stored_xss_poc.py`) nie działa na Vercel — uruchamiaj go lokalnie wobec docelowego API.
- Dane Stored XSS są w **localStorage przeglądarki** użytkownika (nie na serwerze Vercel).
- Nie dodawaj restrykcyjnego CSP w nagłówkach Vercel — lab celowo testuje wykonanie skryptów w przeglądarce.

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
