import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import './App.css'

const STORAGE_KEY = 'xss-lab-stored-entries'

function generateMarker() {
  const hex = crypto.randomUUID().replace(/-/g, '').slice(0, 8)
  return `XSS-STORED-POC-${hex}`
}

const PRESET_PAYLOADS = [
  {
    id: 'plain-marker',
    label: 'Marker tekstowy',
    build: (marker) => `[${marker}]`,
  },
  {
    id: 'img-onerror',
    label: 'img onerror (alert)',
    build: () => '<img src=x onerror=alert(1)>',
  },
  {
    id: 'svg-onload',
    label: 'svg onload (console)',
    build: (marker) => `<svg/onload=console.log("${marker}")>`,
  },
  {
    id: 'script-alert',
    label: 'script alert',
    build: () => '<script>alert("XSS")<\/script>',
  },
  {
    id: 'attribute-break',
    label: 'Atrybut (breakout)',
    build: () => '"><img src=x onerror=alert(1)>',
  },
]

const RENDER_MODES = [
  { id: 'innerHTML', label: 'innerHTML (podatne)', desc: 'Bez escapowania — typowy Stored XSS' },
  { id: 'textContent', label: 'textContent (bezpieczne)', desc: 'Treść traktowana jako tekst' },
  { id: 'encode', label: 'encodeURIComponent', desc: 'Escapowanie znaków HTML' },
]

function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function loadStoredEntries() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return raw ? JSON.parse(raw) : []
  } catch {
    return []
  }
}

function VulnerablePreview({ payload, mode, label }) {
  const ref = useRef(null)

  useEffect(() => {
    const el = ref.current
    if (!el) return

    if (mode === 'innerHTML') {
      el.innerHTML = payload
    } else if (mode === 'textContent') {
      el.textContent = payload
    } else {
      el.innerHTML = escapeHtml(payload)
    }
  }, [payload, mode])

  return (
    <div className="preview-block">
      <div className="preview-label">{label}</div>
      <div ref={ref} className="preview-surface" data-testid={`preview-${mode}`} />
    </div>
  )
}

function App() {
  const [tab, setTab] = useState('manual')
  const [marker, setMarker] = useState(generateMarker)
  const [payload, setPayload] = useState('')
  const [renderMode, setRenderMode] = useState('innerHTML')
  const [fieldName, setFieldName] = useState('comment')
  const [entries, setEntries] = useState(loadStoredEntries)
  const [log, setLog] = useState([])

  const addLog = useCallback((type, message) => {
    setLog((prev) => [
      { id: crypto.randomUUID(), type, message, at: new Date().toLocaleTimeString() },
      ...prev.slice(0, 19),
    ])
  }, [])

  useEffect(() => {
    const handler = (event) => {
      const detail = event.detail ?? event.message ?? String(event)
      addLog('exec', `Wykryto wykonanie JS: ${detail}`)
    }

    const origLog = console.log
    console.log = (...args) => {
      origLog.apply(console, args)
      const text = args.map(String).join(' ')
      if (text.includes('XSS-STORED-POC')) {
        addLog('exec', `console.log: ${text}`)
      }
    }

    window.addEventListener('xss-lab-hit', handler)
    return () => {
      console.log = origLog
      window.removeEventListener('xss-lab-hit', handler)
    }
  }, [addLog])

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(entries))
  }, [entries])

  const markerInPayload = payload.includes(marker)

  const htmlSource = useMemo(() => {
    if (renderMode === 'innerHTML') return payload
    if (renderMode === 'encode') return escapeHtml(payload)
    return escapeHtml(payload)
  }, [payload, renderMode])

  function applyPreset(build) {
    const next = build(marker)
    setPayload(next)
    addLog('info', `Wstawiono preset (${next.length} znaków)`)
  }

  function handleStoreSubmit(e) {
    e.preventDefault()
    if (!payload.trim()) return

    const entry = {
      id: crypto.randomUUID(),
      field: fieldName,
      payload,
      marker: markerInPayload ? marker : null,
      createdAt: new Date().toISOString(),
    }
    setEntries((prev) => [entry, ...prev])
    addLog('stored', `Zapisano wpis w polu „${fieldName}”`)
    setPayload('')
  }

  function clearEntries() {
    setEntries([])
    localStorage.removeItem(STORAGE_KEY)
    addLog('info', 'Wyczyszczono zapisane wpisy')
  }

  function regenerateMarker() {
    const next = generateMarker()
    setMarker(next)
    addLog('info', `Nowy marker: ${next}`)
  }

  return (
    <div className="lab">
      <header className="lab-header">
        <div>
          <h1>XSS Lab</h1>
          <p className="subtitle">
            Ręczne testowanie payloadów — tylko na systemach, do których masz autoryzację
          </p>
        </div>
        <div className="marker-box">
          <span className="marker-label">Marker sesji</span>
          <code className="marker-value">{marker}</code>
          <button type="button" className="btn btn-ghost" onClick={regenerateMarker}>
            Odśwież
          </button>
        </div>
      </header>

      <nav className="tabs">
        {[
          ['manual', 'Ręczny tester'],
          ['stored', 'Stored XSS'],
          ['python', 'Skrypt Python'],
        ].map(([id, label]) => (
          <button
            key={id}
            type="button"
            className={`tab ${tab === id ? 'active' : ''}`}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </nav>

      {tab === 'manual' && (
        <section className="panel">
          <div className="grid-2">
            <div className="card">
              <h2>Payload</h2>
              <p className="hint">
                Wklej payload do pola, które zapisuje się na serwerze (komentarz, bio, ticket…).
                W tym labie sprawdzasz, jak zachowa się renderowanie w przeglądarce.
              </p>

              <label className="field">
                <span>Treść payloadu</span>
                <textarea
                  value={payload}
                  onChange={(e) => setPayload(e.target.value)}
                  placeholder={`<svg/onload=console.log("${marker}")>`}
                  rows={6}
                  spellCheck={false}
                />
              </label>

              <div className="presets">
                <span className="presets-label">Presety:</span>
                {PRESET_PAYLOADS.map((p) => (
                  <button
                    key={p.id}
                    type="button"
                    className="btn btn-preset"
                    onClick={() => applyPreset(p.build)}
                  >
                    {p.label}
                  </button>
                ))}
              </div>

              <label className="field">
                <span>Tryb renderowania (symulacja backendu)</span>
                <select value={renderMode} onChange={(e) => setRenderMode(e.target.value)}>
                  {RENDER_MODES.map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.label}
                    </option>
                  ))}
                </select>
                <small>{RENDER_MODES.find((m) => m.id === renderMode)?.desc}</small>
              </label>

              <div className="status-row">
                {markerInPayload ? (
                  <span className="badge badge-ok">Marker obecny w payloadzie</span>
                ) : (
                  <span className="badge badge-warn">Brak markera — trudniej potwierdzić wykonanie</span>
                )}
              </div>
            </div>

            <div className="card">
              <h2>Podgląd na żywo</h2>
              <VulnerablePreview
                payload={payload}
                mode={renderMode === 'encode' ? 'encode' : renderMode}
                label={`Render: ${renderMode}`}
              />

              <div className="preview-block">
                <div className="preview-label">Źródło HTML (to trafi do DOM)</div>
                <pre className="code-block">{htmlSource || '(pusty payload)'}</pre>
              </div>

              <div className="preview-block">
                <div className="preview-label">Atrybut (symulacja value=&quot;…&quot;)</div>
                <input
                  type="text"
                  className="attr-demo"
                  readOnly
                  value={payload}
                  aria-label="Symulacja atrybutu HTML"
                />
                <small className="hint">
                  Jeśli payload zawiera cudzysłowy, może „wyskoczyć” z atrybutu — testuj też ten kontekst.
                </small>
              </div>
            </div>
          </div>
        </section>
      )}

      {tab === 'stored' && (
        <section className="panel">
          <div className="grid-2">
            <div className="card">
              <h2>Zapisz wpis (symulacja POST)</h2>
              <form onSubmit={handleStoreSubmit}>
                <label className="field">
                  <span>Nazwa pola formularza</span>
                  <input
                    value={fieldName}
                    onChange={(e) => setFieldName(e.target.value)}
                    placeholder="comment"
                  />
                </label>

                <label className="field">
                  <span>Payload</span>
                  <textarea
                    value={payload}
                    onChange={(e) => setPayload(e.target.value)}
                    rows={5}
                    spellCheck={false}
                  />
                </label>

                <label className="field">
                  <span>Tryb odczytu (GET / lista)</span>
                  <select value={renderMode} onChange={(e) => setRenderMode(e.target.value)}>
                    {RENDER_MODES.map((m) => (
                      <option key={m.id} value={m.id}>
                        {m.label}
                      </option>
                    ))}
                  </select>
                </label>

                <div className="actions">
                  <button type="submit" className="btn btn-primary">
                    Wyślij i zapisz
                  </button>
                  <button type="button" className="btn btn-ghost" onClick={clearEntries}>
                    Wyczyść wpisy
                  </button>
                </div>
              </form>

              <p className="hint stored-hint">
                Po zapisie odśwież listę po prawej — jeśli marker pojawi się w HTML i wykona JS przy{' '}
                <code>innerHTML</code>, masz silną wskazówkę Stored XSS.
              </p>
            </div>

            <div className="card">
              <h2>Lista zapisanych ({entries.length})</h2>
              {entries.length === 0 ? (
                <p className="empty">Brak wpisów. Wyślij payload, potem sprawdź tę listę.</p>
              ) : (
                <ul className="entry-list">
                  {entries.map((entry) => (
                    <li key={entry.id} className="entry">
                      <div className="entry-meta">
                        <span className="badge">{entry.field}</span>
                        <time>{new Date(entry.createdAt).toLocaleString()}</time>
                      </div>
                      <StoredEntryBody entry={entry} renderMode={renderMode} />
                      <details>
                        <summary>Raw payload</summary>
                        <pre className="code-block">{entry.payload}</pre>
                      </details>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </section>
      )}

      {tab === 'python' && (
        <section className="panel">
          <div className="card card-wide">
            <h2>Automatyczny test (stored_xss_poc.py)</h2>
            <p className="hint">
              Skrypt wysyła payload na wskazany URL, sprawdza marker w odpowiedzi submit i na stronie
              weryfikacji. Plik znajduje się w katalogu projektu.
            </p>
            <pre className="code-block usage">{`python3 stored_xss_poc.py \\
  --submit-url "https://twoja-app.example/api/comments" \\
  --field comment \\
  --verify-url "https://twoja-app.example/comments" \\
  --cookie "session=..." \\
  --extra "post_id=1"`}</pre>
            <p className="hint">
              Opcje: <code>--csrf-field</code> + <code>--csrf-url</code>, <code>--payload-index</code>{' '}
              (0=marker, 1=img, 2=svg), <code>--method GET|POST</code>.
            </p>
          </div>
        </section>
      )}

      <aside className="log-panel">
        <h3>Dziennik wykryć</h3>
        {log.length === 0 ? (
          <p className="empty">Wykonanie payloadu (alert, console.log z markerem) pojawi się tutaj.</p>
        ) : (
          <ul className="log-list">
            {log.map((item) => (
              <li key={item.id} className={`log-item log-${item.type}`}>
                <time>{item.at}</time>
                <span>{item.message}</span>
              </li>
            ))}
          </ul>
        )}
      </aside>

      <footer className="lab-footer">
        <strong>Uwaga:</strong> Używaj wyłącznie na własnych aplikacjach lub za pisemną zgodą (pentest, bug
        bounty, środowisko testowe). Nie testuj obcych serwisów bez autoryzacji.
      </footer>
    </div>
  )
}

function StoredEntryBody({ entry, renderMode }) {
  const ref = useRef(null)

  useEffect(() => {
    const el = ref.current
    if (!el) return

    if (renderMode === 'innerHTML') {
      el.innerHTML = entry.payload
    } else if (renderMode === 'textContent') {
      el.textContent = entry.payload
    } else {
      el.innerHTML = escapeHtml(entry.payload)
    }
  }, [entry.payload, renderMode])

  const markerVisible =
    renderMode === 'innerHTML' &&
    entry.marker &&
    (entry.payload.includes(entry.marker) || entry.payload.includes(`[${entry.marker}]`))

  return (
    <div className="entry-body-wrap">
      {markerVisible && <span className="badge badge-vuln">Marker na liście — możliwy Stored XSS</span>}
      <div ref={ref} className="preview-surface entry-render" />
    </div>
  )
}

export default App
