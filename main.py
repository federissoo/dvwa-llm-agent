"""
main.py — CLI entrypoint for the DVWA multi-agent LangGraph pipeline.

Usage:
    python main.py

Prerequisites:
    1. Copy api_keys.env.example → api_keys.env and fill in credentials.
    2. docker compose up -d   (starts DVWA on 127.0.0.1:4280)
    3. Log in to http://localhost:4280, copy the PHPSESSID cookie value
       and paste it into api_keys.env.
"""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / "api_keys.env")

PHPSESSID: str = os.getenv("PHPSESSID", "")


def _check_prerequisites() -> None:
    """Validate environment before invoking the graph."""
    if not PHPSESSID or PHPSESSID in {"INSERISCI_QUI", ""}:
        print(
            "❌  PHPSESSID non configurato.\n"
            "    Apri api_keys.env e incolla il valore del cookie PHPSESSID\n"
            "    (disponibile dopo il login su http://localhost:4280)."
        )
        sys.exit(1)

    provider = os.getenv("LLM_PROVIDER", "openai").lower()
    if provider == "groq":
        groq_key = os.getenv("GROQ_API_KEY", "")
        if not groq_key or not groq_key.startswith("gsk_"):
            print(
                "❌  GROQ_API_KEY non configurata o non valida per il provider groq.\n"
                "    Controlla api_keys.env."
            )
            sys.exit(1)
    elif provider == "gemini":
        gemini_key = os.getenv("GEMINI_API_KEY", "")
        if not gemini_key or not gemini_key.startswith("AIza"):
            print(
                "❌  GEMINI_API_KEY non configurata o non valida per il provider gemini.\n"
                "    Controlla api_keys.env."
            )
            sys.exit(1)
    else:
        openai_key = os.getenv("OPENAI_API_KEY", "")
        if not openai_key or not openai_key.startswith("sk-"):
            print(
                "❌  OPENAI_API_KEY non configurata o non valida per il provider openai.\n"
                "    Controlla api_keys.env."
            )
            sys.exit(1)


def main() -> None:
    """Run the full DVWA red/blue team agent pipeline."""
    _check_prerequisites()

    # Lazy import so that LLM clients are initialised after env is loaded
    from agent.graph import graph
    from agent.state import AgentState

    langsmith_active = os.getenv("LANGCHAIN_TRACING_V2", "false").lower() == "true"
    project = os.getenv("LANGCHAIN_PROJECT", "dvwa-llm-agent")

    print("🚀 Avvio DVWA Agent (LangGraph)")
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
        "judge_patch": {
            "funzionale": False,
            "qualita_codice": "",
            "problemi": "",
            "motivazione": "",
        },
    }

    final_state: AgentState = graph.invoke(initial_state)

    # ── Summary ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("📋  STATO FINALE")
    print("=" * 60)
    print(f"   Tentativi di attacco  : {final_state.get('tentativo', 0)}")
    print(f"   Ultimo payload        : {final_state.get('payload', '—')}")
    print(f"   Attacco riuscito      : {final_state.get('attacco_successo', False)}")
    print(f"   Sessione scaduta      : {final_state.get('sessione_scaduta', False)}")
    print(f"   Patch applicata       : {final_state.get('patch_applicata', False)}")
    print(f"   Tentativi patch       : {final_state.get('tentativo_patch', 0)}")

    judge_a = final_state.get("judge_attacco", {})
    if judge_a and judge_a.get("motivazione"):
        print(f"\n⚖️   Judge Attacco")
        print(f"   Tecnica usata  : {judge_a.get('tecnica_usata', '—')}")
        print(f"   Motivazione    : {judge_a.get('motivazione', '—')}")

    judge_p = final_state.get("judge_patch", {})
    if judge_p and judge_p.get("motivazione"):
        print(f"\n⚖️   Judge Patch")
        print(f"   Patch funzionale : {judge_p.get('funzionale', False)}")
        print(f"   Qualità codice   : {judge_p.get('qualita_codice', '—')}")
        print(f"   Problemi         : {judge_p.get('problemi', '—')}")
        print(f"   Motivazione      : {judge_p.get('motivazione', '—')}")

    print("=" * 60)


if __name__ == "__main__":
    main()
