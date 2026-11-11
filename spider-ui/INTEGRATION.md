# SPIDER UI Integration Guide

This guide is written for engineers connecting SPIDER UI to a real analysis backend.

---

## 1. How to Run

From the `spider-ui/` directory:

```bash
# 1. Install dependencies
npm install

# 2. Run the local development server (uses Mock backend by default)
npm run dev

# 3. Run type checking
npm run typecheck

# 4. Run automated unit and boundary tests
npm test

# 5. Build for production distribution
npm run build
```

---

## 2. Folder Layout

| Directory / File | Description |
| :--- | :--- |
| `src/backend/` | Unified backend interface (`types.ts`), mock implementation (`mock.ts`), real HTTP client stub (`http.ts`), data validator (`parseRecord.ts`), and verified static research dataset (`results.json`). |
| `src/app/` | Top-level routing (`App.tsx`) and tool hub/sidebar environment definitions (`environments.ts`). |
| `src/components/` | Reusable UI chrome, pages (`WorkbenchPages.tsx`), standalone tool guides (`ToolPages.tsx`), research findings (`ResearchPage.tsx`), tool hub (`ToolHub.tsx`), and the interactive 2D projected canvas scene (`SpiderScene.tsx`). |
| `src/components/overview/` | Hero scroll experience (`ExperienceOverview.tsx`), artwork layers (`ExperienceArtwork.tsx`), and hooks (`useChapterScroll.ts`, `useExperienceMotion.ts`). |
| `src/state/` | Application state management store using Zustand (`workbench.ts`). |
| `src/styles/` | CSS design tokens (`tokens.css` - strictly preserved), experience animations (`experience.css`), and workbench styling (`workbench.css`). |
| `src/tests/` | Automated unit tests (`frontend.test.ts`) validating parsing, verbatim verdict mapping, markdown escaping, and forbidden words. |

---

## 3. Backend Interface (`SpiderBackend`)

Defined in `src/backend/types.ts`:

```ts
export interface SpiderBackend {
  scan(input: File | { path: string }, onProgress?: (p: { stage: string; done?: number; total?: number }) => void): Promise<{ scan_id: string }>;
  getScan(id: string): Promise<ScanRecord>;       // throws NotFound, never substitutes
  listScans(): Promise<ScanRecord[]>;
  hunterRoots(): Promise<string[]>;
  hunt(opts: { roots?: string[] }, onProgress?: (p: { stage: string }) => void): Promise<HuntResult>;
  allow?(sha256: string, note?: string): Promise<void>;
  getResults(): Promise<unknown>;                 // results.json shape
}
```

### Method Specifications

- **`scan(input, onProgress)`**:
  - *Called by*: Package Scanner > Scan (`/scanner/scan`).
  - *Expects*: Either a browser `File` object (.whl, .tar.gz) or an object `{ path: string }` pointing to an unpackaged local folder. Optional `onProgress` callback receives stage and step counts.
  - *Returns*: `{ scan_id: string }`.
  - *Errors*: Throws an `Error` if the backend is unreachable or parsing/dispatch fails.

- **`getScan(id)`**:
  - *Called by*: Package Scanner > Result (`/scanner/result`), Evidence (`/scanner/evidence`), Score (`/scanner/score`), Report (`/scanner/report`), and History (`/history/*`).
  - *Expects*: The exact `scan_id` string.
  - *Returns*: A complete `ScanRecord` conforming to `src/backend/types.ts`.
  - *Errors*: Must throw an error (`"This exact record is unavailable."` or `NotFoundError`) if `id` is not found. It **must never substitute** another record.

- **`listScans()`**:
  - *Called by*: History and Reports (`/history/history`, `/history/reports`).
  - *Returns*: An array of `ScanRecord[]` sorted chronologically.
  - *Errors*: Throws if unavailable.

- **`hunterRoots()`**:
  - *Called by*: Environment Hunter > Scan (`/hunter/scan`).
  - *Returns*: An array of candidate filesystem path strings (e.g. standard virtualenv `site-packages` directories).
  - *Errors*: Throws if discovering roots fails.

- **`hunt(opts, onProgress)`**:
  - *Called by*: Environment Hunter > Scan (`/hunter/scan`) and Hunter > Report (`/hunter/report`).
  - *Expects*: Optional `{ roots?: string[] }`.
  - *Returns*: A `HuntResult` containing detected installed items, distributions count, coverage metrics, and limitations.
  - *Errors*: Throws if environment inspection fails.

- **`allow(sha256, note)`** *(Optional)*:
  - *Called by*: Environment Hunter > Report (`/hunter/report`).
  - *Expects*: File SHA-256 hash and an optional note.
  - *Returns*: `Promise<void>`.
  - *Note*: If not implemented on the backend instance, the "Allow this file" action remains disabled with the tooltip `"Needs the local backend"`.

- **`getResults()`**:
  - *Called by*: Research Results (`/research`).
  - *Returns*: The verified test figures matching `results.json`.

---

## 4. Record Shapes & UI Field Usage

> **Strict Verdict Rule**: The UI displays `verdict.outcome` and `reasons` exactly as received from the backend and **never recomputes, overrides, or fabricates a verdict**.

### `ScanRecord`

| Field | Read by UI | Ignored / Extra |
| :--- | :--- | :--- |
| `scan_id` | **Yes** — Used as unique key and routing parameter | |
| `target.name` | **Yes** — Displayed in headers and history table | |
| `target.version` | **Yes** — Displayed alongside target name | |
| `target.hash_verified` | **Yes** — Shown in collapsed inspection details | |
| `created_at` | **Yes** — Displayed in history table and metadata | |
| `verdict.outcome` | **Yes** — Must be one of: `'suspicious'`, `'none_detected_in_this_scan'`, `'unable_to_assess'` | |
| `verdict.reasons` | **Yes** — Displayed as chips (human-labelled, raw ID in tooltip) | |
| `verdict.review_recommended`| **Yes** — Triggers amber "Review recommended" badge | |
| `verdict.limitations` | **Yes** — Listed in details and exported report | |
| `findings[].severity` | **Yes** — Grouping (HIGH, MEDIUM, LOW) & badges | |
| `findings[].indicator` | **Yes** — Displayed in evidence table | |
| `findings[].category` | **Yes** — Displayed and used for category filter | |
| `findings[].file` | **Yes** — Displayed with line number (`file:line`) | |
| `findings[].span.start_line` | **Yes** — Displayed in line location | |
| `findings[].explanation` | **Yes** — Description column in evidence table | |
| `findings[].snippet` | **Yes** — Code snippet column in evidence table | |
| `inventory.files_total` | **Yes** — Summary statistics and details | |
| `inventory.files_inspected`| **Yes** — Summary statistics (`files_inspected / files_total`) | |
| `inventory.python_files`| **Yes** — Summary statistics | |
| `inventory.parse_failures`| **Yes** — Count shown in details | |
| `inventory.uninspected` | **Yes** — Listed in details | |
| `ml.model` | **Yes** — Shown on `/scanner/score` if connected | |
| `ml.malicious_probability` | **Yes** — Shown on `/scanner/score` if connected | |
| `ml.calibrated` | **Yes** — Shown on `/scanner/score` if connected | |
| *Extra fields* | **Ignored** — Stripped by `parseRecord()` | Any arbitrary fields |

### `HuntResult`

| Field | Read by UI | Ignored / Extra |
| :--- | :--- | :--- |
| `hunt_id` | **Yes** — Displayed in header | |
| `created_at` | **Yes** — Displayed in header | |
| `roots` | **Yes** — Listed as inspected paths | |
| `distributions_count`| **Yes** — Displayed as primary metric | |
| `items[].artifact` | **Yes** — Displayed in findings table | |
| `items[].reason` | **Yes** — Displayed in findings table | |
| `items[].path` | **Yes** — Displayed in findings table | |
| `items[].severity` | **Yes** — Grouping (HIGH, MEDIUM, LOW) | |
| `items[].evidence_snippet` | **Yes** — Displayed in findings table | |
| `items[].priority` | **Yes** — Displayed in findings table | |
| `items[].allowlisted` | **Yes** — Filtered behind "Show N allowlisted" button | |
| `coverage.counts` | **Yes** — Displayed in coverage details breakdown | |
| `limitations` | **Yes** — Listed in limitations details | |

### `results.json`

| Field | Read by UI | Ignored / Extra |
| :--- | :--- | :--- |
| `corpus.*` | **Yes** — Corpus signals card | |
| `false_positive.*`| **Yes** — Validation false-positive check card | |
| `evasion.*` | **Yes** — Adversarial evasion batch card | |
| `limits[]` | **Yes** — Known limits card | |

---

## 5. Connecting the Real Backend

The real backend is `spider/api.py` in the repository root, started with `python -m spider serve` (port 8000, loopback only). It serves the built UI and the `/api/*` endpoints below, so for a normal run you only need: `VITE_BACKEND=http npm run build`, then `python -m spider serve`. For development, run `python -m spider serve` in one terminal and `VITE_BACKEND=http npm run dev` in another; Vite proxies `/api` to it.

Notes on the real API: `GET /api/explain` is not implemented (Astra is not connected; the UI does not call it). Hunter paths are returned with the home directory shown as `~`. `/api/results` serves `results/ui_results.json`, a copy of `src/backend/results.json`; keep the two in sync.

To wire the UI to your live Python or service backend:

1. **Environment Variable**: Set `VITE_BACKEND=http` in `.env` or during launch:
   ```bash
   VITE_BACKEND=http npm run dev
   ```
2. **Vite Proxy / Target**: By default Vite proxies `/api` requests to `http://127.0.0.1:8000`. Set `VITE_API_TARGET=http://127.0.0.1:8000` (or your custom backend address) in your environment to change the proxy target. You can also customize the Vite development port with `VITE_DEV_PORT` (default: `5173`).
3. **Loopback Only**: All archive uploads and scanning operations should be hosted on loopback (`127.0.0.1` / `localhost`) to prevent unauthorized cross-origin transmission of untrusted archives. Server runs with strict loopback binding (`host: '127.0.0.1'`).
4. **Endpoint Specifications**:

| Method | Endpoint | Request Body | Response Body |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/scan` | `multipart/form-data` with `archive: File` OR `path: string` | `{ "scan_id": "string" }` |
| `GET` | `/api/scans/:id` | None | `ScanRecord` JSON |
| `GET` | `/api/scans` | None | `ScanRecord[]` JSON |
| `GET` | `/api/hunter/roots`| None | `string[]` (filesystem paths) |
| `POST` | `/api/hunt` | `{ "roots": ["..."] }` | `HuntResult` JSON |
| `POST` | `/api/hunter/allow` | `{ "sha256": "...", "note": "..." }` | `204 No Content` or `{ "ok": true }` |
| `GET` | `/api/explain` | Query params: `scan_id`, optional `finding_index` | `{ "explanation": "string", "context": "string" }` |
| `GET` | `/api/results` | None | Content of `results.json` |

---

## 6. What Is Not Connected Yet

The following items are intentionally marked or left unconnected:
- **Model score (`/scanner/score`)**: Displays `"Model score: Not connected. The rule-based verdict above is what this scan used."` unless `record.ml` is populated. No synthetic gauges or numbers are invented.
- **Allow-list action (`/hunter/report`)**: The "Allow this file" button is rendered disabled with the tooltip `"Needs the local backend"`.
- **Extension download (`/extension`)**: The "Download" button is rendered disabled with the badge `"Coming soon"`.
- **History persistence beyond the browser**: The mock backend persists records in `localStorage`. Connecting `HttpSpiderBackend` delegates persistence to the backend database.

---

## 7. Routes & Implementation Status

| Route | Page Name | Environment | Status | Backend Method(s) | Data Source |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/` | Welcome | Standalone | **Ready** | None | Static & decorative scene |
| `/hub` | Tool Hub | Standalone | **Ready** | None | Hub environment tiles |
| `/scanner/scan` | Scan Package | Package Scanner | **Ready** | `backend.scan()` | Real contract / mock |
| `/scanner/result` | Result | Package Scanner | **Ready** | `backend.getScan()` | Real contract / mock |
| `/scanner/evidence` | Evidence | Package Scanner | **Ready** | `backend.getScan()` | Real contract / mock |
| `/scanner/score` | Score | Package Scanner | **Preview** | `backend.getScan()` | Real contract / mock (shows "Not connected" if ML absent) |
| `/scanner/report` | Report | Package Scanner | **Ready** | `backend.getScan()` | Generated client-side (JSON/Markdown) |
| `/hunter/scan` | Environment Scan | Environment Hunter | **Ready** | `backend.hunterRoots()`, `backend.hunt()` | Real contract / mock |
| `/hunter/report` | Environment Report | Environment Hunter | **Ready** | `backend.hunt()` | Real contract / mock |
| `/extension` | SPIDER Extension | Standalone | **Coming soon** | None | Static guide |
| `/learn` | How packages attack | Standalone | **Guide** | None | Static guide |
| `/history/history` | Scan History | History and Reports | **Ready** | `backend.listScans()`, `backend.getScan()` | Real contract / mock |
| `/history/reports` | Reports | History and Reports | **Ready** | `backend.listScans()`, `backend.getScan()` | Real contract / mock |
| `/research` | Results | Standalone | **Ready** | `backend.getResults()` | Static verified dataset (`results.json`) |
| `/research/overview` | Overview | Research Lab | **Preview** | `backend.getResults()` | Static verified dataset (`results.json`) |
| `/research/dataset` | Dataset | Research Lab | **Preview** | `backend.getResults()` | Static verified dataset (`results.json`) |
| `/research/signals` | Signals | Research Lab | **Preview** | `backend.getResults()` | Static verified dataset (`results.json`) |
| `/research/models` | Models | Research Lab | **Preview** | None | Explains under review status with planned frames |
| `/research/limits` | Limits | Research Lab | **Preview** | `backend.getResults()` | Static verified dataset (`results.json`) |
| `/redteam/overview` | Overview | Red Team | **Preview** | `backend.getResults()` | Static verified dataset (`results.json`) |
| `/redteam/batch` | Batch | Red Team | **Preview** | `backend.getResults()` | Static verified dataset (`results.json`) |
| `/redteam/techniques` | Techniques | Red Team | **Preview** | None | Illustrative disguise techniques catalog |
| `/redteam/limits` | Limits | Red Team | **Preview** | None | Operational bounds & payload caveats |
| `/settings` | Settings | Standalone | **Ready** | None | Local state (motion & scene quality) |

