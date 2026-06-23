"""
main.py — CLI entrypoint for the DVWA multi-agent LangGraph pipeline.

Usage:
    python main.py

Prerequisites:
    1. Copy api_keys.env.example → api_keys.env and fill in LLM credentials.
    2. Clone https://github.com/digininja/DVWA and docker compose up -d
    3. The agent automatically logs in to DVWA and obtains a fresh PHPSESSID.
"""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / "api_keys.env")

_PROVIDER_KEYS = {
    "groq": ("GROQ_API_KEY", "gsk_"),
    "gemini": ("GEMINI_API_KEY", "AIza"),
    "openai": ("OPENAI_API_KEY", "sk-"),
}


def _check_prerequisites() -> None:
    """Validate environment before invoking the graph."""
    provider = os.getenv("LLM_PROVIDER", "openai").lower()
    env_var, prefix = _PROVIDER_KEYS.get(provider, _PROVIDER_KEYS["openai"])
    key = os.getenv(env_var, "")
    if not key or not key.startswith(prefix):
        print(
            f"❌  {env_var} non configurata o non valida per il provider {provider}.\n"
            "    Controlla api_keys.env."
        )
        sys.exit(1)


def main() -> None:
    """Run the full DVWA red/blue team agent pipeline."""
    _check_prerequisites()

    # Lazy import so that LLM clients are initialised after env is loaded
    from agent.graph import graph
    from agent.nodes import PATH_FILE_VULNERABILE
    from agent.state import AgentState

    langsmith_active = os.getenv("LANGCHAIN_TRACING_V2", "false").lower() == "true"
    project = os.getenv("LANGCHAIN_PROJECT", "dvwa-llm-agent")

    print("Avvio DVWA Agent (LangGraph)")
    if langsmith_active:
        print(f"   📊 Tracciamento LangSmith attivo — progetto: {project}")
        print("      Visualizza su: https://smith.langchain.com")
    print()

    initial_state: AgentState = {
        "messages": [],
        "tentativo": 0,
        "payload": "",
        "risposta_http_raw": "",
        "attacco_successo": False,
        "sessione_scaduta": False,
        "judge_attacco": {
            "successo": False,
            "motivazione": "",
            "tecnica_usata": "",
            "suggerimento": "",
        },
        "codice_originale": "",
        "patch_applicata": False,
        "tentativo_patch": 0,
        "regression_test_passed": True,
        "judge_patch": {
            "funzionale": False,
            "qualita_codice": "",
            "problemi": "",
            "motivazione": "",
        },
        "num_diff_applicati_successo": 0,
        "num_test_funzionali_passati": 0,
        "num_errori_sintassi": 0,
        "dettagli_sintassi": [],
        "dettagli_applicazione": [],
    }

    # Save original PHP source for cleanup at exit
    original_php = (
        PATH_FILE_VULNERABILE.read_text(encoding="utf-8")
        if PATH_FILE_VULNERABILE.exists()
        else None
    )

    try:
        final_state: AgentState = graph.invoke(initial_state)
    finally:
        if original_php and PATH_FILE_VULNERABILE.exists():
            PATH_FILE_VULNERABILE.write_text(original_php, encoding="utf-8")
            print("🔄 File DVWA ripristinato al codice originale.")

    # ── Summary ──────────────────────────────────────────────────────────────
    sep = "=" * 60
    print(f"\n{sep}\n📋  STATO FINALE\n{sep}")
    for label, key, default in [
        ("Tentativi di attacco", "tentativo", 0),
        ("Ultimo payload", "payload", "—"),
        ("Attacco riuscito", "attacco_successo", False),
        ("Sessione scaduta", "sessione_scaduta", False),
        ("Patch applicata", "patch_applicata", False),
        ("Tentativi patch", "tentativo_patch", 0),
    ]:
        print(f"   {label:<22}: {final_state.get(key, default)}")

    # ── Metriche Richieste da CLAUDE.md ──────────────────────────────────────
    tp = final_state.get("tentativo_patch", 0)
    final_functional = final_state.get("judge_patch", {}).get("funzionale", False)
    pct = lambda n: (n / tp * 100) if tp > 0 else 0.0

    metrics = [
        (
            "Exploit Blocking Rate",
            f"{100.0 if (tp > 0 and final_functional) else 0.0:.1f}%",
        ),
        (
            "Preservation of Business Logic",
            f"{pct(final_state.get('num_test_funzionali_passati', 0)):.1f}%",
        ),
        (
            "Patch Applicability",
            f"{pct(final_state.get('num_diff_applicati_successo', 0)):.1f}%",
        ),
        (
            "Syntax & Runtime Errors",
            f"{final_state.get('num_errori_sintassi', 0)} fallimenti",
        ),
        ("LLM Iterations", str(tp)),
    ]
    print("\n📊  METRICHE VALUTAZIONE (CLAUDE.md)")
    for label, value in metrics:
        print(f"   {label:<34}: {value}")

    for icon, title, key in [
        ("⚠️", "Dettagli Conflitti Applicazione Patch", "dettagli_applicazione"),
        ("⚠️", "Dettagli Errori Sintassi PHP", "dettagli_sintassi"),
    ]:
        items = final_state.get(key, [])
        if items:
            print(f"\n{icon}   {title}:")
            for err in items:
                print(f"     - {err}")

    judge_a = final_state.get("judge_attacco", {})
    if judge_a and judge_a.get("motivazione"):
        print(f"\n⚖️   Judge Attacco")
        print(f"   Tecnica usata  : {judge_a.get('tecnica_usata', '—')}")
        print(f"   Motivazione    : {judge_a.get('motivazione', '—')}")

    judge_p = final_state.get("judge_patch", {})
    if judge_p and judge_p.get("motivazione"):
        print(f"\n⚖️   Judge Patch")
        for label, key in [
            ("Patch funzionale", "funzionale"),
            ("Qualità codice", "qualita_codice"),
            ("Problemi", "problemi"),
            ("Motivazione", "motivazione"),
        ]:
            print(f"   {label:<18}: {judge_p.get(key, '—')}")

    print(sep)


if __name__ == "__main__":
    main()
