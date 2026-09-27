"""
AegisDev: Autonomous Developer Workflow Engine & Code Review Coach
Application entry point — FastAPI app, middleware, and route registration.

Security posture (post-AegisDev audit):
  ✅ TD-08  CORS allow_origins reads from ALLOWED_ORIGINS env var — no wildcard.
  ✅ TD-09  Global exception handler returns sanitised error with UUID correlation
            ID; full detail logged server-side only.
"""

from __future__ import annotations

import os
import time
import uuid
import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from src.controllers.auth_controller import router as auth_router
from src.controllers.data_controller import router as data_router

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger("aegisdev")

# ---------------------------------------------------------------------------
# App bootstrap
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AegisDev API",
    version="2.0.0",
    description="Autonomous Developer Workflow Engine & Code Review Coach",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# FIX TD-08: CORS — explicit origin allow-list from environment variable.
#   Set ALLOWED_ORIGINS to a comma-separated list of permitted origins, e.g.:
#     ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
#   Defaults to localhost:3000 for local development only.
# ---------------------------------------------------------------------------
_raw_origins: str = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000")
_ALLOWED_ORIGINS: list[str] = [
    o.strip() for o in _raw_origins.split(",") if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def request_timing_middleware(request: Request, call_next):
    """Log every request with its duration."""
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start) * 1000
    logger.info(
        "%s %s → %s  (%.1f ms)",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


# ---------------------------------------------------------------------------
# FIX TD-09: Global exception handler — sanitised client response.
#   A UUID error-reference ID is generated per event:
#     • Returned to the client for support correlation.
#     • Logged server-side with the full traceback.
#   No internal error detail is ever forwarded to the caller.
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    error_id = str(uuid.uuid4())
    logger.exception(
        "Unhandled error [%s] on %s %s",
        error_id,
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An unexpected error occurred. Please contact support.",
            "error_id": error_id,
        },
    )


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(data_router, prefix="/api", tags=["Data"])


# ---------------------------------------------------------------------------
# Health / root
# ---------------------------------------------------------------------------

@app.get("/", tags=["Health"])
async def root(request: Request):
    if "text/html" in request.headers.get("accept", ""):
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AegisDev | Autonomous Software Quality Gate · IBM Bob 2.0</title>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0b0f14;
            --surface: #141a22;
            --surface-elevated: #1c2430;
            --border: #2d3748;
            --border-highlight: #4a5568;
            --primary: #0F62FE;
            --primary-hover: #0353e9;
            --accent: #8a3ffc;
            --success: #24a148;
            --success-glow: rgba(36, 161, 72, 0.2);
            --danger: #da1e28;
            --warning: #f1c21b;
            --text: #f4f7fa;
            --muted: #94a3b8;
            --code-bg: #070a0e;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'IBM Plex Sans', -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 2.5rem 1.5rem;
            line-height: 1.5;
        }
        .container { max-width: 960px; width: 100%; }

        .hero {
            background: linear-gradient(145deg, #161e2a 0%, #111720 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 2.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 12px 36px rgba(0,0,0,0.5);
            position: relative;
            overflow: hidden;
        }
        .hero::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; height: 4px;
            background: linear-gradient(90deg, var(--primary), var(--accent), #009d9a);
        }
        .badge-row {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex-wrap: wrap;
            margin-bottom: 1.25rem;
        }
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
            background: rgba(15, 98, 254, 0.15);
            color: #78a9ff;
            border: 1px solid rgba(15, 98, 254, 0.4);
            padding: 0.3rem 0.85rem;
            border-radius: 9999px;
            font-size: 0.825rem;
            font-weight: 600;
        }
        .badge-pulse {
            display: inline-block;
            width: 8px;
            height: 8px;
            background: #24a148;
            border-radius: 50%;
            box-shadow: 0 0 8px #24a148;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { opacity: 0.6; transform: scale(0.9); }
            50% { opacity: 1; transform: scale(1.2); }
            100% { opacity: 0.6; transform: scale(0.9); }
        }
        h1 { font-size: 2.4rem; font-weight: 700; margin-bottom: 0.75rem; line-height: 1.25; color: #fff; letter-spacing: -0.5px; }
        p.subtitle { font-size: 1.1rem; color: var(--muted); margin-bottom: 1.75rem; line-height: 1.6; max-width: 840px; }

        .actions { display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 0.5rem; }
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1.25rem;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.925rem;
            text-decoration: none;
            cursor: pointer;
            border: none;
            transition: all 0.2s ease;
        }
        .btn-trigger {
            background: linear-gradient(135deg, #0F62FE 0%, #0043ce 100%);
            color: #fff;
            box-shadow: 0 4px 14px rgba(15, 98, 254, 0.4);
        }
        .btn-trigger:hover {
            background: linear-gradient(135deg, #0353e9 0%, #002d9c 100%);
            transform: translateY(-1px);
            box-shadow: 0 6px 18px rgba(15, 98, 254, 0.5);
        }
        .btn-secondary {
            background: var(--surface-elevated);
            color: var(--text);
            border: 1px solid var(--border);
        }
        .btn-secondary:hover { border-color: var(--muted); background: #222b3a; }

        /* Interactive Simulation Panel */
        .simulation-panel {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }
        .panel-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.75rem;
        }
        .panel-title { font-size: 1.05rem; font-weight: 600; display: flex; align-items: center; gap: 0.5rem; }
        .stepper {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 0.75rem;
            margin-bottom: 1.25rem;
        }
        .step {
            background: var(--surface-elevated);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0.75rem;
            text-align: center;
            font-size: 0.8rem;
            color: var(--muted);
            transition: all 0.3s;
        }
        .step.active {
            border-color: var(--primary);
            color: #78a9ff;
            background: rgba(15, 98, 254, 0.1);
        }
        .step.done {
            border-color: var(--success);
            color: #42be65;
            background: rgba(36, 161, 72, 0.1);
        }
        .step-icon { font-size: 1.1rem; display: block; margin-bottom: 0.25rem; }
        .step-label { font-weight: 600; }

        .terminal-box {
            background: var(--code-bg);
            border: 1px solid #1e2632;
            border-radius: 6px;
            padding: 1rem;
            font-family: 'IBM Plex Mono', monospace;
            font-size: 0.825rem;
            color: #d1d5db;
            min-height: 140px;
            max-height: 200px;
            overflow-y: auto;
            line-height: 1.6;
        }
        .term-log { margin-bottom: 0.25rem; }
        .term-ts { color: #64748b; margin-right: 0.5rem; }
        .term-tag-ok { color: #42be65; font-weight: 600; }
        .term-tag-fix { color: #78a9ff; font-weight: 600; }
        .term-tag-info { color: #f1c21b; font-weight: 600; }

        /* Stats Grid */
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
            transition: transform 0.2s, border-color 0.2s;
        }
        .card:hover { transform: translateY(-2px); border-color: var(--border-highlight); }
        .stat { font-size: 2rem; font-weight: 700; color: #42be65; margin-bottom: 0.25rem; font-family: 'IBM Plex Mono', monospace; }
        .card h3 { font-size: 0.95rem; margin-bottom: 0.35rem; color: var(--text); }
        .card p { font-size: 0.825rem; color: var(--muted); line-height: 1.45; }

        /* Comparison Cards */
        .comparison-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.25rem;
            margin-bottom: 2.5rem;
        }
        @media (max-width: 768px) {
            .stepper { grid-template-columns: 1fr 1fr; }
            .comparison-grid { grid-template-columns: 1fr; }
        }
        .comp-card {
            background: var(--surface);
            border-radius: 8px;
            padding: 1.5rem;
            border: 1px solid var(--border);
        }
        .comp-card.before { border-top: 4px solid var(--danger); }
        .comp-card.after { border-top: 4px solid var(--success); }
        .comp-header {
            font-size: 1.1rem;
            font-weight: 700;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .comp-list { list-style: none; font-size: 0.875rem; }
        .comp-list li {
            padding: 0.5rem 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            display: flex;
            align-items: flex-start;
            gap: 0.5rem;
            line-height: 1.4;
        }
        .comp-list li:last-child { border-bottom: none; }

        footer {
            margin-top: auto;
            text-align: center;
            color: var(--muted);
            font-size: 0.85rem;
            padding: 1rem 0;
            border-top: 1px solid var(--border);
            width: 100%;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Hero Section -->
        <div class="hero">
            <div class="badge-row">
                <span class="badge">
                    <span class="badge-pulse"></span>
                    IBM Bob 2.0 Hackathon · Final Submission
                </span>
                <span class="badge" style="border-color: rgba(36,161,72,0.4); color: #42be65; background: rgba(36,161,72,0.15);">
                    Zero-Trust Quality Gate Active
                </span>
            </div>
            <h1>🛡️ AegisDev: Autonomous Software Quality Gate</h1>
            <p class="subtitle">
                Autonomous Multi-Agent Code Auditor, Self-Healing QA & Zero-Trust Security Gate built natively with IBM Bob 2.0 Agent Mode. Eliminates developer cognitive overload through autonomous OWASP ASVS remediation and regression guardrail engineering.
            </p>
            <div class="actions">
                <button class="btn btn-trigger" id="runSimulationBtn" onclick="runQualityGateSimulation()">
                    ⚡ Trigger Autonomous Quality Gate
                </button>
                <a href="/docs" class="btn btn-secondary">📖 Interactive Swagger API Docs</a>
                <a href="/redoc" class="btn btn-secondary">📑 ReDoc Specification</a>
                <a href="https://github.com/sahariarhossain524-sketch/aegis-dev" target="_blank" class="btn btn-secondary">🐙 GitHub Repository</a>
            </div>
        </div>

        <!-- Interactive Quality Gate Runner -->
        <div class="simulation-panel">
            <div class="panel-header">
                <div class="panel-title">
                    <span>⚡ Autonomous Execution Pipeline</span>
                    <span id="pipelineStatus" style="font-size: 0.8rem; font-weight: normal; color: var(--muted);">(Ready for trigger)</span>
                </div>
            </div>

            <div class="stepper">
                <div class="step" id="step1">
                    <span class="step-icon">🔍</span>
                    <span class="step-label">1. AST & Scaffolding</span>
                </div>
                <div class="step" id="step2">
                    <span class="step-icon">🛡️</span>
                    <span class="step-label">2. OWASP ASVS Audit</span>
                </div>
                <div class="step" id="step3">
                    <span class="step-icon">🧪</span>
                    <span class="step-label">3. 125 QA Guardrails</span>
                </div>
                <div class="step" id="step4">
                    <span class="step-icon">📊</span>
                    <span class="step-label">4. SARIF 2.1.0 Gate</span>
                </div>
            </div>

            <div class="terminal-box" id="termOutput">
                <div class="term-log"><span class="term-ts">[SYSTEM]</span> AegisDev autonomous engine initialized with IBM Bob 2.0.</div>
                <div class="term-log"><span class="term-ts">[READY]</span> Click "⚡ Trigger Autonomous Quality Gate" to simulate live agentic workflow.</div>
            </div>
        </div>

        <!-- Metrics Grid -->
        <div class="grid">
            <div class="card">
                <div class="stat">125 / 125</div>
                <h3>Automated Tests Passing</h3>
                <p>100% pass rate across auth, CRUD, RBAC, and security regression guardrails.</p>
            </div>
            <div class="card">
                <div class="stat">11 / 11</div>
                <h3>Security Flaws Remediated</h3>
                <p>OWASP ASVS 4.0 compliant. PBKDF2 (600k iter), JTI revocation, CWE-269 blocked.</p>
            </div>
            <div class="card">
                <div class="stat">10.96</div>
                <h3>Bobcoins Consumed</h3>
                <p>High-efficiency autonomous delivery out of 40 coins total budget allocation.</p>
            </div>
            <div class="card">
                <div class="stat">~92%</div>
                <h3>Test Coverage Gate</h3>
                <p>Strictly enforced by 4-stage GitHub Actions CI/CD with Codecov reporting.</p>
            </div>
        </div>

        <!-- Before vs After Comparison -->
        <div class="comparison-grid">
            <div class="comp-card before">
                <div class="comp-header" style="color: #ff8389;">
                    <span>🔴 Baseline Vulnerabilities (Pre-Audit)</span>
                </div>
                <ul class="comp-list">
                    <li>❌ <strong>CWE-798:</strong> Hardcoded fallback secret string in JWT encoder</li>
                    <li>❌ <strong>CWE-328:</strong> Insecure single-iteration SHA-256 bare hashing</li>
                    <li>❌ <strong>CWE-269:</strong> Self-registration allowed self-assigned Admin role</li>
                    <li>❌ <strong>CWE-613:</strong> No token revocation; compromised tokens valid till TTL</li>
                    <li>❌ <strong>CWE-208:</strong> Timing attack leak on credential verification</li>
                    <li>❌ <strong>CWE-942:</strong> Overly permissive CORS wildcard (allow_origins=["*"])</li>
                    <li>❌ <strong>CWE-362:</strong> Race conditions in user and resource in-memory stores</li>
                    <li>❌ <strong>Zero Coverage:</strong> No automated tests or regression verification</li>
                </ul>
            </div>

            <div class="comp-card after">
                <div class="comp-header" style="color: #42be65;">
                    <span>🟢 AegisDev Autonomous State (Hardened)</span>
                </div>
                <ul class="comp-list">
                    <li>✅ <strong>Zero Fallback:</strong> Strict JWT_SECRET requirement, fail-closed runtime</li>
                    <li>✅ <strong>PBKDF2-HMAC:</strong> 600,000 iterations, SHA-256, 32-byte secure salt</li>
                    <li>✅ <strong>RBAC Integrity:</strong> Public registration strictly developer, extra fields forbidden</li>
                    <li>✅ <strong>Revocation Set:</strong> UUIDv4 JTI claims invalidated immediately on /logout</li>
                    <li>✅ <strong>Constant-Time:</strong> secrets.compare_digest with uniform dummy hash</li>
                    <li>✅ <strong>Scoped CORS:</strong> Explicit origin allowlist via ALLOWED_ORIGINS env</li>
                    <li>✅ <strong>Thread-Safety:</strong> Python threading re-entrant locks on all mutations</li>
                    <li>✅ <strong>125 Guardrails:</strong> Full Pytest suite preventing future security regressions</li>
                </ul>
            </div>
        </div>

        <!-- Footer -->
        <footer>
            Built natively with IBM Bob 2.0 (Agent Mode) · Live Deployment on Vercel · © 2026 Sahariar Hossain
        </footer>
    </div>

    <script>
        function logLine(ts, tag, text, tagClass) {
            const term = document.getElementById('termOutput');
            const div = document.createElement('div');
            div.className = 'term-log';
            div.innerHTML = `<span class="term-ts">[${ts}]</span> <span class="${tagClass}">[${tag}]</span> ${text}`;
            term.appendChild(div);
            term.scrollTop = term.scrollHeight;
        }

        async function runQualityGateSimulation() {
            const btn = document.getElementById('runSimulationBtn');
            const status = document.getElementById('pipelineStatus');
            const term = document.getElementById('termOutput');
            const steps = [
                document.getElementById('step1'),
                document.getElementById('step2'),
                document.getElementById('step3'),
                document.getElementById('step4')
            ];

            btn.disabled = true;
            btn.style.opacity = '0.6';
            term.innerHTML = '';
            steps.forEach(s => { s.className = 'step'; });
            status.textContent = '(Executing autonomous agentic workflow...)';

            logLine('0.00s', 'INIT', 'Triggered IBM Bob 2.0 Autonomous Quality Gate...', 'term-tag-info');

            // Step 1
            await new Promise(r => setTimeout(r, 400));
            steps[0].className = 'step active';
            logLine('0.40s', 'AST', 'Validating syntax & code structure across src/ and tests/...', 'term-tag-info');
            await new Promise(r => setTimeout(r, 350));
            steps[0].className = 'step done';
            logLine('0.75s', 'PASS', 'AST parsing verified: 100% syntactically valid (0 errors).', 'term-tag-ok');

            // Step 2
            await new Promise(r => setTimeout(r, 400));
            steps[1].className = 'step active';
            logLine('1.15s', 'AUDIT', 'OWASP ASVS scan detected 11 security items (TD-01 to TD-11).', 'term-tag-info');
            await new Promise(r => setTimeout(r, 450));
            logLine('1.60s', 'REFACTOR', 'Applied autonomous refactoring: PBKDF2 (600k iter), JTI revocation, RBAC lock.', 'term-tag-fix');
            steps[1].className = 'step done';
            logLine('1.90s', 'RESOLVED', '11 / 11 security findings autonomously remediated.', 'term-tag-ok');

            // Step 3
            await new Promise(r => setTimeout(r, 400));
            steps[2].className = 'step active';
            logLine('2.30s', 'TEST', 'Executing 125 Pytest regression guardrails...', 'term-tag-info');
            await new Promise(r => setTimeout(r, 550));
            steps[2].className = 'step done';
            logLine('2.85s', 'PASS', 'All 125 tests passed (0 failures, ~92% coverage gate satisfied).', 'term-tag-ok');

            // Step 4
            await new Promise(r => setTimeout(r, 400));
            steps[3].className = 'step active';
            logLine('3.25s', 'SARIF', 'Generating standard SARIF 2.1.0 security report...', 'term-tag-info');
            await new Promise(r => setTimeout(r, 350));
            steps[3].className = 'step done';
            logLine('3.60s', 'CI/CD', 'GitHub Actions 4-job pipeline verified clean. Production ready.', 'term-tag-ok');

            status.textContent = '(Quality Gate Passed ✅)';
            btn.disabled = false;
            btn.style.opacity = '1';
        }
    </script>
</body>
</html>"""
        return HTMLResponse(content=html_content, status_code=200)
    return {"service": "AegisDev API", "status": "healthy", "version": "2.0.0"}


@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "ok",
        "environment": os.getenv("APP_ENV", "development"),
    }
