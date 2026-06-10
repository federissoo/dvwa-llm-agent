"""
agent/nodes.py — All LangGraph node functions for the DVWA multi-agent pipeline.

Node responsibilities:
    node_init           — Reads vulnerable PHP file once; stores in state.
    node_red_team       — Generates SQL injection payloads via LLM.
    node_esegui_attacco — Pure HTTP function; establishes attack success fact.
    node_judge_attacco  — LLM reasoning about attack; does NOT decide fact.
    node_feedback_attacco — Injects failure feedback into red team message history.
    node_blue_team      — Generates PHP patch from codice_originale.
    node_feedback_patch — Injects patch failure feedback for blue team retry.
    node_valida_patch   — Re-runs HTTP attack to verify patch effectiveness.
    node_judge_patch    — LLM reasoning about patch quality.
"""

import json
import os
import re
import subprocess
import time
from pathlib import Path

import requests
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from agent.prompts import (
    BLUE_TEAM_SYSTEM,
    prompt_red_team_iniziale,
    prompt_blue_team,
    prompt_feedback_attacco,
    prompt_feedback_patch,
    prompt_judge_attacco,
    prompt_judge_patch,
)
from agent.state import AgentState, JudgeAttaccoResult, JudgePatchResult

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / "api_keys.env")

DVWA_SQLI_URL: str = "http://127.0.0.1:4280/vulnerabilities/sqli/"

# Auto-detect DVWA source file location or read from DVWA_PATH env variable
_dvwa_path_env = os.getenv("DVWA_PATH")
if _dvwa_path_env:
    PATH_FILE_VULNERABILE: Path = Path(_dvwa_path_env) / "vulnerabilities" / "sqli" / "source" / "low.php"
else:
    _path_local = BASE_DIR / "DVWA" / "vulnerabilities" / "sqli" / "source" / "low.php"
    _path_sibling = BASE_DIR.parent / "DVWA" / "vulnerabilities" / "sqli" / "source" / "low.php"
    if not _path_local.exists() and _path_sibling.exists():
        PATH_FILE_VULNERABILE: Path = _path_sibling
    else:
        PATH_FILE_VULNERABILE: Path = _path_local

PHPSESSID: str = os.getenv("PHPSESSID", "INSERISCI_QUI")

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

def _extract_payload(text: str) -> str:
    """Extracts the raw SQL injection payload from LLM response content,
    handling markdown blocks, trailing explanations, thoughts, and prefixes.
    """
    # Remove thought tags if present
    text = re.sub(r"<thought>.*?</thought>", "", text, flags=re.DOTALL)
    text = re.sub(r".*?</thought>", "", text, flags=re.DOTALL)
    
    # Strip markdown code blocks
    if "```sql" in text:
        text = text.split("```sql")[1].split("```")[0]
    elif "```" in text:
        text = text.split("```")[1].split("```")[0]
        
    text = text.strip().replace("`", "")
    
    # Split by lines and clean them
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    if not lines:
        return ""
        
    # Search backwards for a line that isn't just explanatory text
    for line in reversed(lines):
        clean_line = re.sub(r'^(payload|il payload è|ecco il payload|payload:|code:|sql:)\s*', '', line, flags=re.IGNORECASE).strip()
        if (clean_line.startswith("'") and clean_line.endswith("'")) or (clean_line.startswith('"') and clean_line.endswith('"')):
            clean_line = clean_line[1:-1].strip()
        if clean_line:
            return clean_line
            
    return lines[-1]


def _strip_markdown_fences(text: str) -> str:
    """Remove ```php or ``` fences that an LLM may still emit despite instructions."""
    if "```php" in text:
        return text.split("```php")[1].split("```")[0].strip()
    if "```" in text:
        return text.split("```")[1].split("```")[0].strip()
    return text.strip()


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


def _extract_unified_diff(text: str) -> str:
    """Extracts the Unified Diff block from the LLM output."""
    # Remove thought tags
    text = re.sub(r"<thought>.*?</thought>", "", text, flags=re.DOTALL)
    text = re.sub(r".*?</thought>", "", text, flags=re.DOTALL)
    
    # Strip markdown fences if present
    if "```diff" in text:
        text = text.split("```diff")[1].split("```")[0]
    elif "```patch" in text:
        text = text.split("```patch")[1].split("```")[0]
    elif "```php" in text:
        text = text.split("```php")[1].split("```")[0]
    elif "```" in text:
        text = text.split("```")[1].split("```")[0]
        
    text = text.strip()
    
    # Locate where the actual diff structure starts (--- or +++ or @@ or diff --git)
    lines = text.splitlines()
    diff_lines = []
    started = False
    for line in lines:
        if line.startswith("---") or line.startswith("+++") or line.startswith("@@") or line.startswith("diff --git"):
            started = True
        if started:
            diff_lines.append(line)
            
    if not diff_lines:
        return text
        
    return "\n".join(diff_lines)


def _recalculate_diff_hunk_headers(diff_content: str) -> str:
    """
    Parses a unified diff and corrects the line counts in the hunk headers (@@ -start,len +start,len @@).
    LLMs frequently count the number of lines incorrectly, which causes the 'patch' command to fail.
    """
    lines = diff_content.splitlines()
    new_lines = []
    
    hunk_lines = []
    current_header = None
    
    def process_hunk(header: str, h_lines: list[str]) -> str:
        # Match @@ -old_start[,old_len] +new_start[,new_len] @@
        match = re.match(r"^@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@(.*)$", header)
        if not match:
            return header
        old_start = int(match.group(1))
        new_start = int(match.group(2))
        suffix = match.group(3)
        
        # Count lines
        old_len = 0
        new_len = 0
        for line in h_lines:
            if line.startswith("-"):
                old_len += 1
            elif line.startswith("+"):
                new_len += 1
            else:
                # Context line (starts with space)
                old_len += 1
                new_len += 1
                
        return f"@@ -{old_start},{old_len} +{new_start},{new_len} @@{suffix}"

    for line in lines:
        if line.startswith("@@"):
            if current_header:
                new_lines.append(process_hunk(current_header, hunk_lines))
                new_lines.extend(hunk_lines)
                hunk_lines = []
            current_header = line
        elif current_header is not None:
            hunk_lines.append(line)
        else:
            new_lines.append(line)
            
    if current_header:
        new_lines.append(process_hunk(current_header, hunk_lines))
        new_lines.extend(hunk_lines)
        
    return "\n".join(new_lines)


def _find_first_context_line_num(cleaned_lines: list[str], original_code: str) -> int:
    # Find the first line that is a context line (not diff metadata and not starting with - or +)
    first_context = None
    for line in cleaned_lines:
        if line.startswith("---") or line.startswith("+++") or line.startswith("@@") or line.startswith("diff --git"):
            continue
        if not line.startswith("-") and not line.startswith("+"):
            # Context line!
            first_context = line.strip()
            if first_context:
                break
                
    if not first_context:
        return 1
        
    # Find this line in original_code
    orig_lines = original_code.splitlines()
    for idx, orig_line in enumerate(orig_lines):
        if first_context in orig_line:
            return idx + 1 # 1-based line number
            
    return 1


def _apply_patch(target_file: Path, diff_content: str, original_code: str) -> tuple[bool, str]:
    """
    Applies the unified diff content to the target file using 'patch -t'.
    Returns (success, error_message).
    """
    # Clean diff content from leading spaces or stray characters
    lines = diff_content.splitlines()
    cleaned_lines = []
    started_diff = False
    for line in lines:
        if line.startswith("---") or line.startswith("+++") or line.startswith("@@") or line.startswith("diff --git") or line.startswith(" ") or line.startswith("-") or line.startswith("+"):
            started_diff = True
        if started_diff:
            cleaned_lines.append(line)
            
    # Check if hunk header @@ is missing
    has_hunk_header = any(l.startswith("@@") for l in cleaned_lines)
    if not has_hunk_header:
        # Recalculate start line from first context line
        start_line = _find_first_context_line_num(cleaned_lines, original_code)
        
        # Prepend a dummy hunk header
        new_lines = []
        inserted = False
        for line in cleaned_lines:
            new_lines.append(line)
            if line.startswith("+++") and not inserted:
                new_lines.append(f"@@ -{start_line},1 +{start_line},1 @@")
                inserted = True
        if not inserted:
            new_lines.insert(0, f"@@ -{start_line},1 +{start_line},1 @@")
        cleaned_lines = new_lines

    diff_content = "\n".join(cleaned_lines)

    # Fix LLM line counting errors in hunk headers
    diff_content = _recalculate_diff_hunk_headers(diff_content)

    diff_file = target_file.parent / "temp_patch.diff"
    
    # Make sure we have the --- and +++ headers, prepending if missing
    has_headers = any(l.startswith("---") for l in cleaned_lines[:3]) and any(l.startswith("+++") for l in cleaned_lines[:3])
    if not has_headers:
        diff_content = f"--- {target_file.name}\n+++ {target_file.name}\n" + diff_content
        
    diff_file.write_text(diff_content, encoding="utf-8")
    try:
        # Run patch tool inside the target directory using the relative filename
        res = subprocess.run(
            ["patch", "-t", "-l", target_file.name, str(diff_file)],
            cwd=str(target_file.parent),
            capture_output=True,
            text=True,
            timeout=5
        )
        if res.returncode == 0:
            return True, ""
        else:
            err = res.stderr or res.stdout or "Diff application failed (conflict)"
            return False, err
    except Exception as e:
        return False, str(e)
    finally:
        if diff_file.exists():
            diff_file.unlink()


def _lint_php_file(file_path: Path) -> tuple[bool, str]:
    """Runs php -l to perform syntax validation on the file."""
    for php_cmd in ["php", "/opt/homebrew/bin/php"]:
        try:
            res = subprocess.run(
                [php_cmd, "-l", str(file_path)],
                capture_output=True,
                text=True,
                timeout=5
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


def login_to_dvwa(session: requests.Session) -> bool:
    """
    Logs in to DVWA programmatically using standard credentials (admin/password)
    and updates the session.
    """
    login_url = "http://127.0.0.1:4280/login.php"
    print("🔑 [LOGIN] Autenticazione in corso su DVWA (admin/password)...")
    try:
        # 1. GET login page to obtain the user_token
        res = session.get(login_url, timeout=5)
        token_match = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]", res.text)
        token = token_match.group(1) if token_match else None
        
        # 2. POST to login
        data = {
            "username": "admin",
            "password": "password",
            "Login": "Login"
        }
        if token:
            data["user_token"] = token
            
        res2 = session.post(login_url, data=data, timeout=5)
        if "login.php" not in res2.url:
            print("✅ [LOGIN] Autenticato con successo.")
            return True
        else:
            print("⚠️ [LOGIN] Autenticazione fallita: reindirizzato a login.php.")
            return False
    except Exception as e:
        print(f"❌ [LOGIN] Errore durante l'autenticazione: {e}")
        return False


def reset_dvwa_database() -> bool:
    """
    Resets the DVWA database via setup.php, and logs back in to obtain
    a valid authenticated PHPSESSID session.
    """
    global PHPSESSID
    setup_url = "http://127.0.0.1:4280/setup.php"
    print("\n🔄 [RESET DATABASE] Ripristino del database DVWA...")
    session = requests.Session()
    try:
        # 1. GET setup.php anonymously to get CSRF token
        res = session.get(setup_url, timeout=5)
        token_match = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]", res.text)
        token = token_match.group(1) if token_match else None
        
        # 2. POST to reset database
        data = {"create_db": "Create / Reset Database"}
        if token:
            data["user_token"] = token
            
        res2 = session.post(setup_url, data=data, timeout=5)
        
        # Wait a moment for database creation
        time.sleep(1)
        
        # 3. Log in to establish the authenticated session
        if login_to_dvwa(session):
            new_sessid = session.cookies.get("PHPSESSID")
            if new_sessid:
                PHPSESSID = new_sessid
                print(f"🔑 [RESET DATABASE] Sessione aggiornata con PHPSESSID: {PHPSESSID}")
                return True
        
        print("⚠️ [RESET DATABASE] Reset completato ma login fallito.")
        return False
    except Exception as e:
        print(f"❌ [RESET DATABASE] Errore durante il reset del database: {e}")
        return False


def _run_regression_test() -> tuple[bool, str]:
    """Runs functional regression testing checking if legitimate business logic is preserved."""
    cookies = {"PHPSESSID": PHPSESSID, "security": "low"}
    params = {"id": "1", "Submit": "Submit"}
    try:
        res = requests.get(DVWA_SQLI_URL, params=params, cookies=cookies, timeout=5)
        if "login.php" in res.url:
            return False, "Session expired (redirected to login.php)"
            
        # Check for DB errors
        db_errors = ["sql syntax", "mysqli_error", "sqlite3 exception", "database error"]
        res_lower = res.text.lower()
        for err in db_errors:
            if err in res_lower:
                return False, f"Database error detected in response: {err}"
                
        if "First name: admin" in res.text:
            return True, ""
        else:
            return False, "Legitimate functionality broken: 'First name: admin' not found in response for id=1"
    except Exception as e:
        return False, f"Regression test failed with exception: {e}"


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

    Input state keys used:  (none)
    Output state keys:      codice_originale, risposta_http_raw (error msg)
    """
    print(f"\n🔧 [INIT] Lettura file vulnerabile: {PATH_FILE_VULNERABILE}")
    if not PATH_FILE_VULNERABILE.exists():
        print(f"❌ [INIT] File non trovato: {PATH_FILE_VULNERABILE}")
        return {
            "codice_originale": "",
            "risposta_http_raw": f"ERRORE INIT: file non trovato → {PATH_FILE_VULNERABILE}",
            "sessione_scaduta": True,  # triggers early exit
        }
    codice = PATH_FILE_VULNERABILE.read_text(encoding="utf-8")
    print(f"✅ [INIT] File letto ({len(codice)} caratteri).")

    # Resetta il database all'avvio per garantire esperimenti puliti
    reset_dvwa_database()

    return {"codice_originale": codice}


def node_red_team(state: AgentState) -> dict:
    """
    Red Team node — generates an SQL injection payload via LLM.

    On the first attempt (``tentativo == 0``) it builds a fresh conversation
    with the system + initial human messages.  On subsequent attempts it
    reuses the existing message history (which includes prior failure feedback).

    Input state keys used:  tentativo, messages
    Output state keys:      messages, payload, tentativo
    """
    print(f"\n🔴 [RED TEAM] Tentativo {state['tentativo'] + 1} di {MAX_TENTATIVI}...")

    if state["tentativo"] == 0:
        messages = prompt_red_team_iniziale()
    else:
        messages = state["messages"]

    response = llm.invoke(messages)
    payload = _extract_payload(response.content)
    print(f"🔴 [RED TEAM] Payload generato: {payload}")

    return {
        "messages": messages + [response],
        "payload": payload,
        "tentativo": state["tentativo"] + 1,
    }


def node_esegui_attacco(state: AgentState) -> dict:
    """
    Pure HTTP execution node — the ONLY source of ground truth for attack success.

    Sends the current payload to DVWA and counts ``First name:`` occurrences
    in the response body.  ≥2 occurrences means the injection dumped multiple
    users → attack succeeded.

    This function is deliberately side-effect free (no disk writes) so it can
    be called identically from both the red team loop and ``node_valida_patch``.

    Input state keys used:  payload
    Output state keys:      risposta_http_raw, attacco_successo, sessione_scaduta
    """
    payload: str = state["payload"]
    cookies = {"PHPSESSID": PHPSESSID, "security": "low"}
    params = {"id": payload, "Submit": "Submit"}

    print(f"\n[HTTP] GET {DVWA_SQLI_URL} | id={payload}")

    try:
        res = requests.get(DVWA_SQLI_URL, params=params, cookies=cookies, timeout=5)

        if "login.php" in res.url:
            print("⚠️  [HTTP] Sessione scaduta — reindirizzato a login.php")
            return {
                "risposta_http_raw": "SESSIONE SCADUTA: reindirizzato a login.php — aggiorna PHPSESSID in api_keys.env",
                "attacco_successo": False,
                "sessione_scaduta": True,
            }

        first_names: int = res.text.count("First name:")
        testo_pulito: str = " ".join(re.sub("<.*?>", " ", res.text).split())

        if first_names >= 2:
            print(f"✅ [HTTP] SUCCESSO — trovati {first_names} record 'First name:'")
            return {
                "risposta_http_raw": testo_pulito[:2000],
                "attacco_successo": True,
                "sessione_scaduta": False,
            }

        print(f"❌ [HTTP] FALLITO — solo {first_names} record 'First name:'")
        return {
            "risposta_http_raw": testo_pulito[:2000],
            "attacco_successo": False,
            "sessione_scaduta": False,
        }

    except requests.exceptions.ConnectionError as exc:
        return {
            "risposta_http_raw": f"ERRORE DI CONNESSIONE: {exc}",
            "attacco_successo": False,
            "sessione_scaduta": False,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "risposta_http_raw": f"ERRORE INATTESO: {exc}",
            "attacco_successo": False,
            "sessione_scaduta": False,
        }


def node_judge_attacco(state: AgentState) -> dict:
    """
    Attack judge node — LLM reasoning about *why* the attack succeeded or failed.

    The factual result (``attacco_successo``) is established by
    ``node_esegui_attacco`` and is passed to this node as ground truth.
    The judge MUST NOT override that fact — ``result["successo"]`` is always
    forced to ``state["attacco_successo"]`` after JSON parsing.

    Input state keys used:  attacco_successo, payload, risposta_http_raw
    Output state keys:      judge_attacco (does NOT modify attacco_successo)
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

    # ⚠️  Force ground truth — LLM reasoning must not override the fact
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

    Input state keys used:  risposta_http_raw, judge_attacco, messages
    Output state keys:      messages
    """
    judge = state.get("judge_attacco", {})
    print(f"⚠️  [FEEDBACK ATTACCO] Payload fallito, costruisco feedback...")

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
    Blue Team node — generates a secure PHP patch in Unified Diff format,
    applies it, and lints the result.

    Always restores and reads ``state["codice_originale"]`` as the base —
    never reads the file from disk, which may already contain a broken prior patch.

    Increments ``tentativo_patch`` on each call.

    Input state keys used:  codice_originale, payload, judge_attacco, tentativo_patch,
                            num_diff_applicati_successo, num_errori_sintassi,
                            dettagli_sintassi, dettagli_applicazione
    Output state keys:      patch_applicata, tentativo_patch, num_diff_applicati_successo,
                            num_errori_sintassi, dettagli_sintassi, dettagli_applicazione
    """
    tentativo_patch: int = state.get("tentativo_patch", 0)
    print(f"\n🔵 [BLUE TEAM] Generazione patch (tentativo {tentativo_patch + 1})...")

    codice_originale: str = state.get("codice_originale", "")
    if not codice_originale:
        print("❌ [BLUE TEAM] codice_originale vuoto — impossibile generare patch.")
        return {"patch_applicata": False, "tentativo_patch": tentativo_patch + 1}

    # Ripristina sempre il file al codice originale pulito prima di applicare la patch
    PATH_FILE_VULNERABILE.write_text(codice_originale, encoding="utf-8")
    time.sleep(1)  # synchronise with disk/Docker mount

    judge: dict = state.get("judge_attacco", {})
    tecnica_usata: str = judge.get("tecnica_usata", "SQL Injection")

    prompt: str = prompt_blue_team(
        codice_originale=codice_originale,
        payload=state["payload"],
        tecnica_usata=tecnica_usata,
    )

    response = llm.invoke([
        SystemMessage(content=BLUE_TEAM_SYSTEM),
        HumanMessage(content=prompt),
    ])

    diff_content: str = _extract_unified_diff(response.content)
    print(f"🔵 [BLUE TEAM] Estratto Unified Diff per l'applicazione:\n{diff_content}\n---")

    # Recupera i contatori correnti dallo stato
    diff_successo = state.get("num_diff_applicati_successo", 0)
    errori_sintassi = state.get("num_errori_sintassi", 0)
    lista_sintassi = list(state.get("dettagli_sintassi", []))
    lista_applicazione = list(state.get("dettagli_applicazione", []))

    # Tenta l'applicazione del diff unificato
    success_patch, err_patch = _apply_patch(PATH_FILE_VULNERABILE, diff_content, codice_originale)

    if not success_patch:
        print(f"❌ [BLUE TEAM] Applicazione della patch fallita (conflitto): {err_patch}")
        lista_applicazione.append(f"Tentativo {tentativo_patch + 1}: {err_patch}")
        return {
            "patch_applicata": False,
            "tentativo_patch": tentativo_patch + 1,
            "dettagli_applicazione": lista_applicazione,
        }

    # Patch applicata con successo sul file
    print("✅ [BLUE TEAM] Patch (diff) applicata con successo.")
    diff_successo += 1
    time.sleep(2)  # allow Docker volume to sync

    # Esegui PHP Linting check
    success_lint, err_lint = _lint_php_file(PATH_FILE_VULNERABILE)
    if not success_lint:
        print(f"❌ [BLUE TEAM] Errore di sintassi PHP (Linting fallito): {err_lint}")
        errori_sintassi += 1
        lista_sintassi.append(f"Tentativo {tentativo_patch + 1}: {err_lint}")
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
    """
    Blue team feedback node — appends patch failure context for the next attempt.

    Passes the patch judge's ``problemi`` and ``motivazione`` back to the blue
    team so it can produce an improved patch.

    Input state keys used:  judge_patch, codice_originale, payload, judge_attacco
    Output state keys:      messages (appends feedback; blue team re-reads on next call)
    """
    judge_p = state.get("judge_patch", {})
    judge_a = state.get("judge_attacco", {})
    print("⚠️  [FEEDBACK PATCH] Patch fallita, costruisco feedback per blue team...")

    content = prompt_feedback_patch(
        codice_originale=state.get("codice_originale", ""),
        payload=state["payload"],
        tecnica_usata=judge_a.get("tecnica_usata", "SQL Injection"),
        problemi=judge_p.get("problemi", "Non specificati"),
        motivazione=judge_p.get("motivazione", ""),
    )

    # We don't use `messages` for blue team history (it belongs to red team),
    # so we store the feedback in a transient messages append that blue team
    # can optionally inspect — the actual prompt is rebuilt by node_blue_team.
    # This node primarily serves as a routing waypoint that preserves context.
    feedback = HumanMessage(content=content)
    return {"messages": [feedback]}


def node_valida_patch(state: AgentState) -> dict:
    """
    Patch validation node — re-executes the attack against the patched code
    and runs a functional regression test to verify that legitimate business
    logic is preserved, resetting the database beforehand.

    Input state keys used:  payload, num_test_funzionali_passati
    Output state keys:      risposta_http_raw, attacco_successo, sessione_scaduta,
                            num_test_funzionali_passati
    """
    print("\n🔄 [VALIDAZIONE] Inizio validazione patch (Dual-Verification)...")

    # Recupera il contatore corrente dallo stato
    funzionali_passati = state.get("num_test_funzionali_passati", 0)

    # 1. Reset database to ensure reproducible validation tests
    reset_dvwa_database()

    # 2. Security Test: Re-run the offensive payload
    print("\n🔄 [VALIDAZIONE] 1/2. Esecuzione Security Test (exploit)...")
    risultato: dict = node_esegui_attacco(state)

    # 3. Functional Regression Test: Verify legitimate application behaviour
    print("\n🔄 [VALIDAZIONE] 2/2. Esecuzione Functional Regression Test...")
    success_reg, err_reg = _run_regression_test()

    if success_reg:
        print("✅ REGRESSIONE FUNZIONALE: Le funzionalità legittime dell'applicazione funzionano correttamente.")
        funzionali_passati += 1
    else:
        print(f"❌ REGRESSIONE FUNZIONALE FALLITA: {err_reg}")
        # Se le funzionalità legittime si rompono, la patch non è valida.
        # Forziamo attacco_successo=True per indicare fallimento della patch nel grafo.
        risultato["attacco_successo"] = True
        risultato["risposta_http_raw"] = (
            f"ERRORE REGRESSIONE: {err_reg}\n\n" + risultato.get("risposta_http_raw", "")
        )[:2000]

    if not risultato["attacco_successo"] and success_reg:
        print("✅ VALIDAZIONE COMPLETATA: La patch ha superato con successo entrambi i test!")
    else:
        print("❌ VALIDAZIONE COMPLETATA: La patch ha fallito i test di sicurezza o funzionali.")

    risultato["num_test_funzionali_passati"] = funzionali_passati
    return risultato


def node_judge_patch(state: AgentState) -> dict:
    """
    Patch judge node — LLM evaluation of patch correctness and code quality.

    The factual result (whether the patch blocked the attack) is already
    determined by ``node_valida_patch`` via ``state["attacco_successo"]``.
    The judge MUST NOT override that fact — ``result["funzionale"]`` is
    forced to ``not state["attacco_successo"]`` after JSON parsing.

    Input state keys used:  attacco_successo, payload, risposta_http_raw
    Output state keys:      judge_patch, patch_applicata
    """
    print("\n⚖️  [JUDGE PATCH] Analisi in corso...")

    patch_funzionale: bool = not state["attacco_successo"]
    fatto: str = "BLOCCATO (patch funzionale)" if patch_funzionale else "PASSATO (patch non funzionale)"

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
    print(f"⚖️  [JUDGE PATCH] {icon_f} funzionale | {judge_result['qualita_codice']} qualità")

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
    """
    Route after node_judge_attacco.

    Returns:
        'end_sessione'    — DVWA session expired.
        'blue_team'       — Attack succeeded; hand off to blue team.
        'feedback_attacco'— Attack failed but retries remain.
        'END'             — Attack failed and retries exhausted.
    """
    from langgraph.graph import END  # local import to avoid circular dependency

    if state.get("sessione_scaduta", False):
        return "end_sessione"
    if state["attacco_successo"]:
        return "blue_team"
    if state["tentativo"] >= MAX_TENTATIVI:
        print(f"\n⚠️  Tentativi di attacco esauriti ({MAX_TENTATIVI}). Sistema non violato.")
        return END
    return "feedback_attacco"


def decide_dopo_blue_team(state: AgentState) -> str:
    """
    Route after node_blue_team.

    Always routes to 'valida_patch' to allow validation (and subsequent retries)
    even if patch application or compilation linting failed.
    """
    return "valida_patch"


def decide_dopo_judge_patch(state: AgentState) -> str:
    """
    Route after node_judge_patch.

    Returns:
        'feedback_patch' — Patch failed and patch retries remain.
        'END'            — Patch succeeded, or patch retries exhausted.
    """
    from langgraph.graph import END

    judge = state.get("judge_patch", {})
    tentativo_patch: int = state.get("tentativo_patch", 0)

    if not judge.get("funzionale", True) and tentativo_patch < MAX_TENTATIVI_PATCH:
        print(f"⚠️  Patch non funzionale — tentativo patch {tentativo_patch}/{MAX_TENTATIVI_PATCH}")
        return "feedback_patch"
    return END
