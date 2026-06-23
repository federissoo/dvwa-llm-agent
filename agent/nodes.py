"""
agent/nodes.py — All LangGraph node functions for the DVWA multi-agent pipeline.

Node responsibilities:
    node_init           — Reads vulnerable PHP file once; stores in state.
    node_red_team       — Generates SQL injection payloads via LLM.
    node_esegui_attacco — Pure HTTP function; establishes attack success fact.
    node_judge_attacco  — LLM reasoning about attack; does NOT decide fact.
    node_feedback_attacco — Injects failure feedback into red team message history.
    node_blue_team      — Generates corrected PHP file, writes it, computes diff for reporting.
    node_feedback_patch — Injects patch failure feedback for blue team retry.
    node_valida_patch   — Re-runs HTTP attack to verify patch effectiveness.
    node_judge_patch    — LLM reasoning about patch quality.
"""

import difflib
import json
import os
import re
import subprocess
import time
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END

from agent.dvwa_client import DVWAClient
from agent.prompts import (
    BLUE_TEAM_SYSTEM,
    prompt_blue_team,
    prompt_feedback_attacco,
    prompt_feedback_patch,
    prompt_judge_attacco,
    prompt_judge_patch,
    prompt_red_team_iniziale,
)
from agent.state import AgentState, JudgeAttaccoResult, JudgePatchResult

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

dvwa = DVWAClient(os.getenv("DVWA_BASE_URL", "http://127.0.0.1:4280"))

# Auto-detect DVWA source file location or read from DVWA_PATH env variable
_dvwa_path_env = os.getenv("DVWA_PATH")
if _dvwa_path_env:
    PATH_FILE_VULNERABILE: Path = (
        Path(_dvwa_path_env) / "vulnerabilities" / "sqli" / "source" / "low.php"
    )
else:
    _path_local = BASE_DIR / "DVWA" / "vulnerabilities" / "sqli" / "source" / "low.php"
    _path_sibling = (
        BASE_DIR.parent / "DVWA" / "vulnerabilities" / "sqli" / "source" / "low.php"
    )
    if not _path_local.exists() and _path_sibling.exists():
        PATH_FILE_VULNERABILE: Path = _path_sibling
    else:
        PATH_FILE_VULNERABILE: Path = _path_local

MAX_TENTATIVI: int = 3
MAX_TENTATIVI_PATCH: int = 2

# LLM instances — determined by LLM_PROVIDER env variable
llm_provider = os.getenv("LLM_PROVIDER", "openai").lower()

if llm_provider == "groq":
    _groq_api_key = os.getenv("GROQ_API_KEY", "")
    _groq_model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    _groq_judge_model = os.getenv("GROQ_JUDGE_MODEL", "llama-3.3-70b-versatile")
    llm: ChatOpenAI = ChatOpenAI(
        model=_groq_model,
        api_key=_groq_api_key,
        base_url="https://api.groq.com/openai/v1",
        temperature=0.0,
    )
    llm_judge: ChatOpenAI = ChatOpenAI(
        model=_groq_judge_model,
        api_key=_groq_api_key,
        base_url="https://api.groq.com/openai/v1",
        temperature=0.0,
    )
elif llm_provider == "gemini":
    _gemini_api_key = os.getenv("GEMINI_API_KEY", "")
    _gemini_model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    _gemini_judge_model = os.getenv("GEMINI_JUDGE_MODEL", "gemini-2.5-pro")
    llm: ChatOpenAI = ChatOpenAI(
        model=_gemini_model,
        openai_api_key=_gemini_api_key,
        base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        temperature=0.0,
    )
    llm_judge: ChatOpenAI = ChatOpenAI(
        model=_gemini_judge_model,
        openai_api_key=_gemini_api_key,
        base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        temperature=0.0,
    )
else:
    llm: ChatOpenAI = ChatOpenAI(model="gpt-3.5-turbo", temperature=0.0)
    llm_judge: ChatOpenAI = ChatOpenAI(model="gpt-3.5-turbo", temperature=0.0)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _strip_thought_tags(text: str) -> str:
    """Remove <thought>…</thought> blocks from LLM output."""
    text = re.sub(r"<thought>.*?</thought>", "", text, flags=re.DOTALL)
    return re.sub(r".*?</thought>", "", text, flags=re.DOTALL)


def _strip_markdown_fences(text: str, *langs: str) -> str:
    """Remove ```lang or ``` fences. Check langs in order, then bare ```."""
    for lang in langs:
        tag = f"```{lang}"
        if tag in text:
            return text.split(tag)[1].split("```")[0].strip()
    if "```" in text:
        return text.split("```")[1].split("```")[0].strip()
    return text.strip()


def _extract_payload(text: str) -> str:
    """Extracts the raw SQL injection payload from LLM response content."""
    text = _strip_thought_tags(text)
    text = _strip_markdown_fences(text, "sql")
    text = text.replace("`", "").strip()

    lines = [line.strip() for line in text.split("\n") if line.strip()]
    if not lines:
        return ""

    for line in reversed(lines):
        clean = re.sub(
            r"^(payload|il payload è|ecco il payload|payload:|code:|sql:)\s*",
            "",
            line,
            flags=re.IGNORECASE,
        ).strip()
        if (clean.startswith("'") and clean.endswith("'")) or (
            clean.startswith('"') and clean.endswith('"')
        ):
            clean = clean[1:-1].strip()
        if clean:
            return clean

    return lines[-1]


def _parse_json_response(raw: str) -> dict:
    """
    Parse a JSON response from the LLM, stripping any surrounding markdown fences.

    Args:
        raw: Raw LLM response string.

    Returns:
        Parsed dict. Raises json.JSONDecodeError on failure.
    """
    clean = _strip_markdown_fences(raw)
    # Fix: normalizza i booleani Python → JSON
    clean = clean.replace(": True", ": true").replace(": False", ": false")
    return json.loads(clean)


def _extract_php_code(text: str) -> str:
    """Extracts the PHP code block from the LLM output."""
    text = _strip_thought_tags(text)
    text = _strip_markdown_fences(text, "php")
    return text.strip()


def _compute_unified_diff(original: str, patched: str, filename: str = "low.php") -> str:
    """Computes a unified diff between two strings for reporting."""
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
        )
    )


def _lint_php_file(file_path: Path) -> tuple[bool, str]:
    """Runs php -l to perform syntax validation on the file."""
    for php_cmd in ["php", "/opt/homebrew/bin/php"]:
        try:
            res = subprocess.run(
                [php_cmd, "-l", str(file_path)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0:
                return True, ""
            else:
                return False, res.stdout or res.stderr or "Syntax check failed"
        except FileNotFoundError:
            continue
        except Exception as e:
            return False, str(e)
    return True, "PHP interpreter not found, skipping syntax check"


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


def node_init(state: AgentState) -> dict:
    """
    Initialisation node — runs once at graph start.

    Reads the vulnerable PHP source from disk and stores it in
    ``state["codice_originale"]``. If the file does not exist the node
    returns ``sessione_scaduta=True`` (abusing the terminal flag) and an
    empty string so the graph exits cleanly via the session-expired edge.
    """
    print(f"\n[INIT] Lettura file vulnerabile: {PATH_FILE_VULNERABILE}")
    if not PATH_FILE_VULNERABILE.exists():
        print(f"❌ [INIT] File non trovato: {PATH_FILE_VULNERABILE}")
        return {
            "codice_originale": "",
            "risposta_http_raw": f"ERRORE INIT: file non trovato → {PATH_FILE_VULNERABILE}",
            "sessione_scaduta": True,  # triggers early exit
        }
    codice = PATH_FILE_VULNERABILE.read_text(encoding="utf-8")
    print(f"[INIT] File letto.")

    dvwa.reset_database()

    return {"codice_originale": codice}


def node_red_team(state: AgentState) -> dict:
    """
    Red Team node — generates an SQL injection payload via LLM.

    On the first attempt (``tentativo == 0``) it builds a fresh conversation
    with the system + initial human messages.  On subsequent attempts it
    reuses the existing message history (which includes prior failure feedback).
    """
    print(f"\n🔴 [RED TEAM] Tentativo {state['tentativo'] + 1} di {MAX_TENTATIVI}...")

    if state["tentativo"] == 0:
        messages = prompt_red_team_iniziale()
    else:
        messages = state["messages"]

    response = llm.invoke(messages)
    payload = _extract_payload(response.content)
    print(f"[RED TEAM] Payload generato: {payload}")

    return {
        "messages": messages + [response],
        "payload": payload,
        "tentativo": state["tentativo"] + 1,
    }


def node_esegui_attacco(state: AgentState) -> dict:
    """Executes the SQLi payload via DVWAClient."""
    return dvwa.execute_sqli(state["payload"])


def node_judge_attacco(state: AgentState) -> dict:
    """
    Attack judge node — LLM reasoning about *why* the attack succeeded or failed.

    The factual result (``attacco_successo``) is established by
    ``node_esegui_attacco`` and is passed to this node as ground truth.
    The judge MUST NOT override that fact — ``result["successo"]`` is always
    forced to ``state["attacco_successo"]`` after JSON parsing.
    """
    print("\n⚖️  [JUDGE ATTACCO] Analisi in corso...")

    fatto: str = "SUCCESSO" if state["attacco_successo"] else "FALLITO"
    prompt: str = prompt_judge_attacco(
        fatto=fatto,
        payload=state["payload"],
        risposta=state["risposta_http_raw"],
    )

    response = llm_judge.invoke([HumanMessage(content=prompt)])

    try:
        result: dict = _parse_json_response(response.content)
    except Exception:  # noqa: BLE001
        result = {
            "successo": state["attacco_successo"],
            "motivazione": response.content[:300],
            "tecnica_usata": "Non determinata",
            "suggerimento": "Riprova con una tecnica diversa.",
        }

    # Force ground truth — LLM reasoning must not override the fact
    result["successo"] = state["attacco_successo"]

    judge_result: JudgeAttaccoResult = {
        "successo": result["successo"],
        "motivazione": result.get("motivazione", ""),
        "tecnica_usata": result.get("tecnica_usata", "Non determinata"),
        "suggerimento": result.get("suggerimento", ""),
    }

    icon = "✅" if judge_result["successo"] else "❌"
    print(f"⚖️  [JUDGE ATTACCO] {icon} {judge_result['motivazione']}")

    return {"judge_attacco": judge_result}


def node_feedback_attacco(state: AgentState) -> dict:
    """
    Red team feedback node — appends attack failure context to message history.

    Enriches the feedback with judge analysis when available.
    """
    judge = state.get("judge_attacco", {})
    print(f"[FEEDBACK ATTACCO] Payload fallito, costruisco feedback...")

    if judge and judge.get("motivazione"):
        content = (
            f"Il tuo attacco è fallito.\n\n"
            f"Analisi: {judge['motivazione']}\n"
            f"Tecnica rilevata: {judge.get('tecnica_usata', 'Non determinata')}\n"
            f"Suggerimento: {judge.get('suggerimento', '')}\n\n"
            "Genera un nuovo payload. Scrivi SOLO il payload."
        )
    else:
        content = prompt_feedback_attacco(state["risposta_http_raw"])

    feedback = HumanMessage(content=content)
    return {"messages": [feedback]}


def node_blue_team(state: AgentState) -> dict:
    """
    Blue Team node — asks the LLM for the full corrected PHP file,
    writes it to disk, computes the unified diff for reporting, and lints.
    """
    tentativo_patch: int = state.get("tentativo_patch", 0)
    print(f"\n🔵 [BLUE TEAM] Generazione patch (tentativo {tentativo_patch + 1})...")

    codice_originale: str = state.get("codice_originale", "")
    if not codice_originale:
        print("❌ [BLUE TEAM] codice_originale vuoto — impossibile generare patch.")
        return {"patch_applicata": False, "tentativo_patch": tentativo_patch + 1}

    judge_a: dict = state.get("judge_attacco", {})
    tecnica_usata: str = judge_a.get("tecnica_usata", "SQL Injection")

    judge_p: dict = state.get("judge_patch", {})
    if tentativo_patch > 0 and judge_p.get("motivazione"):
        prompt: str = prompt_feedback_patch(
            codice_originale=codice_originale,
            payload=state["payload"],
            tecnica_usata=tecnica_usata,
            problemi=judge_p.get("problemi", "Non specificati"),
            motivazione=judge_p.get("motivazione", ""),
        )
    else:
        prompt: str = prompt_blue_team(
            codice_originale=codice_originale,
            payload=state["payload"],
            tecnica_usata=tecnica_usata,
        )

    response = llm.invoke(
        [
            SystemMessage(content=BLUE_TEAM_SYSTEM),
            HumanMessage(content=prompt),
        ]
    )

    codice_patchato: str = _extract_php_code(response.content)

    diff_report = _compute_unified_diff(codice_originale, codice_patchato)
    print(f"🔵 [BLUE TEAM] Diff calcolato:\n{diff_report}\n---")

    diff_successo = state.get("num_diff_applicati_successo", 0)
    errori_sintassi = state.get("num_errori_sintassi", 0)
    lista_sintassi = list(state.get("dettagli_sintassi", []))
    lista_applicazione = list(state.get("dettagli_applicazione", []))

    if not codice_patchato or codice_patchato == codice_originale:
        print("❌ [BLUE TEAM] L'LLM ha restituito codice vuoto o identico all'originale.")
        lista_applicazione.append(f"Tentativo {tentativo_patch + 1}: codice identico o vuoto")
        return {
            "patch_applicata": False,
            "tentativo_patch": tentativo_patch + 1,
            "dettagli_applicazione": lista_applicazione,
        }

    PATH_FILE_VULNERABILE.write_text(codice_patchato, encoding="utf-8")
    diff_successo += 1
    print("✅ [BLUE TEAM] File patchato scritto su disco.")
    time.sleep(2)  # allow Docker volume to sync

    success_lint, err_lint = _lint_php_file(PATH_FILE_VULNERABILE)
    if not success_lint:
        print(f"❌ [BLUE TEAM] Errore di sintassi PHP (Linting fallito): {err_lint}")
        errori_sintassi += 1
        lista_sintassi.append(f"Tentativo {tentativo_patch + 1}: {err_lint}")
        PATH_FILE_VULNERABILE.write_text(codice_originale, encoding="utf-8")
        return {
            "patch_applicata": False,
            "tentativo_patch": tentativo_patch + 1,
            "num_diff_applicati_successo": diff_successo,
            "num_errori_sintassi": errori_sintassi,
            "dettagli_sintassi": lista_sintassi,
            "dettagli_applicazione": lista_applicazione,
        }

    print("✅ [BLUE TEAM] Controllo sintassi PHP superato con successo.")
    return {
        "patch_applicata": True,
        "tentativo_patch": tentativo_patch + 1,
        "num_diff_applicati_successo": diff_successo,
        "num_errori_sintassi": errori_sintassi,
        "dettagli_sintassi": lista_sintassi,
        "dettagli_applicazione": lista_applicazione,
    }


def node_feedback_patch(state: AgentState) -> dict:
    """Routing waypoint — node_blue_team reads judge_patch directly on retry."""
    print(
        "⚠️  [FEEDBACK PATCH] Patch fallita, il blue team riproverà con il feedback del judge."
    )
    return {}


def node_valida_patch(state: AgentState) -> dict:
    """
    Dual-verification node: re-runs the exploit and a regression suite
    against the patched code, after resetting the database.
    """
    print("\n🔄 [VALIDAZIONE] Inizio validazione patch (Dual-Verification)...")

    funzionali_passati = state.get("num_test_funzionali_passati", 0)

    dvwa.reset_database()

    print("\n🔄 [VALIDAZIONE] 1/2. Esecuzione Security Test (exploit)...")
    risultato: dict = dvwa.execute_sqli(state["payload"])

    print("\n🔄 [VALIDAZIONE] 2/2. Esecuzione Functional Regression Tests...")
    success_reg, err_reg = dvwa.run_regression_tests()

    if success_reg:
        print("✅ REGRESSIONE FUNZIONALE: Tutti i test funzionali superati.")
        funzionali_passati += 1
    else:
        print(f"❌ REGRESSIONE FUNZIONALE FALLITA: {err_reg}")
        risultato["risposta_http_raw"] = (
            f"ERRORE REGRESSIONE: {err_reg}\n\n"
            + risultato.get("risposta_http_raw", "")
        )[:2000]

    attack_blocked = not risultato["attacco_successo"]
    if attack_blocked and success_reg:
        print("✅ VALIDAZIONE COMPLETATA: La patch ha superato entrambi i test!")
    else:
        print(
            "❌ VALIDAZIONE COMPLETATA: La patch ha fallito i test di sicurezza o funzionali."
        )

    risultato["regression_test_passed"] = success_reg
    risultato["num_test_funzionali_passati"] = funzionali_passati
    return risultato


def node_judge_patch(state: AgentState) -> dict:
    """
    Patch judge node — LLM evaluation of patch correctness and code quality.

    The factual result (whether the patch blocked the attack) is already
    determined by ``node_valida_patch`` via ``state["attacco_successo"]``.
    The judge MUST NOT override that fact — ``result["funzionale"]`` is
    forced to ``not state["attacco_successo"]`` after JSON parsing.
    """
    print("\n⚖️  [JUDGE PATCH] Analisi in corso...")

    patch_funzionale: bool = not state["attacco_successo"] and state.get(
        "regression_test_passed", True
    )
    fatto: str = (
        "BLOCCATO (patch funzionale)"
        if patch_funzionale
        else "PASSATO (patch non funzionale)"
    )

    codice_patchato: str = ""
    if PATH_FILE_VULNERABILE.exists():
        codice_patchato = PATH_FILE_VULNERABILE.read_text(encoding="utf-8")

    prompt: str = prompt_judge_patch(
        fatto=fatto,
        payload=state["payload"],
        risposta_post_patch=state["risposta_http_raw"],
        codice_patchato=codice_patchato,
    )

    response = llm_judge.invoke([HumanMessage(content=prompt)])

    try:
        result: dict = _parse_json_response(response.content)
    except Exception:  # noqa: BLE001
        result = {
            "funzionale": patch_funzionale,
            "qualita_codice": "non determinata",
            "problemi": "Errore di parsing JSON",
            "motivazione": response.content[:300],
        }

    # ⚠️  Force ground truth — LLM must not override the deterministic fact
    result["funzionale"] = patch_funzionale

    judge_result: JudgePatchResult = {
        "funzionale": result["funzionale"],
        "qualita_codice": result.get("qualita_codice", "non determinata"),
        "problemi": result.get("problemi", ""),
        "motivazione": result.get("motivazione", ""),
    }

    icon_f = "✅" if judge_result["funzionale"] else "❌"
    print(
        f"⚖️  [JUDGE PATCH] {icon_f} funzionale | {judge_result['qualita_codice']} qualità"
    )

    return {"judge_patch": judge_result, "patch_applicata": judge_result["funzionale"]}


# ---------------------------------------------------------------------------
# Conditional edge functions
# ---------------------------------------------------------------------------


def decide_dopo_init(state: AgentState) -> str:
    """
    Route after node_init.

    Returns:
        'end_sessione' if file was not found (sessione_scaduta used as error flag),
        'red_team' otherwise.
    """
    if state.get("sessione_scaduta", False):
        return "end_sessione"
    return "red_team"


def decide_dopo_judge_attacco(state: AgentState) -> str:
    if state.get("sessione_scaduta", False):
        return "end_sessione"
    if state["attacco_successo"]:
        return "blue_team"
    if state["tentativo"] >= MAX_TENTATIVI:
        print(
            f"\n⚠️  Tentativi di attacco esauriti ({MAX_TENTATIVI}). Sistema non violato."
        )
        return END
    return "feedback_attacco"


def decide_dopo_blue_team(_state: AgentState) -> str:
    return "valida_patch"


def decide_dopo_judge_patch(state: AgentState) -> str:
    judge = state.get("judge_patch", {})
    tentativo_patch: int = state.get("tentativo_patch", 0)

    if not judge.get("funzionale", True) and tentativo_patch < MAX_TENTATIVI_PATCH:
        print(
            f"⚠️  Patch non funzionale — tentativo patch {tentativo_patch}/{MAX_TENTATIVI_PATCH}"
        )
        return "feedback_patch"
    return END
