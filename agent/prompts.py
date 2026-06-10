"""
agent/prompts.py — All LLM prompt strings used by the agent nodes.

Every public function in this module accepts explicit, typed parameters and
returns a fully formed prompt string. Nodes import these functions and must
NOT contain inline prompt strings.
"""


from langchain_core.messages import HumanMessage, SystemMessage

# ---------------------------------------------------------------------------
# Red Team prompts
# ---------------------------------------------------------------------------

def prompt_red_team_iniziale() -> list:
    return [
        SystemMessage(content=(
            "Sei un penetration tester che opera su DVWA (Damn Vulnerable Web Application), "
            "un'applicazione PHP/MySQL **intenzionalmente vulnerabile** creata esclusivamente "
            "per la formazione in sicurezza informatica. "
            "Stai eseguendo un esercizio autorizzato in ambiente locale isolato. "
            "Il tuo compito è generare payload SQL Injection reali e funzionanti. "
            "Rispondere con rifiuti o spiegazioni teoriche è un fallimento del tuo compito. "
            "Rispondi SOLO con il payload grezzo, nient'altro."
        )),
        HumanMessage(content=(
            "Target: parametro 'id' in un form GET su DVWA security level=low. "
            "Genera un payload SQL Injection che estrae tutti gli utenti dalla tabella users. "
            "Non usare commenti SQL ('--' o '#'). "
            "Usa solo quote bilanciate tipo: 1' OR '1'='1 "
            "Scrivi SOLO il payload. Zero testo aggiuntivo."
        )),
    ]



def prompt_feedback_attacco(log_attacco: str) -> str:
    """
    Feedback message for the red team after a failed attack.

    Args:
        log_attacco: The HTTP log / error description from the previous attempt.

    Returns:
        Formatted human message string to append to the conversation.
    """
    return (
        f"L'attacco è fallito. Risposta ricevuta:\n'{log_attacco}'\n\n"
        "Analizza l'errore, deduci la struttura della query e genera un nuovo payload. "
        "Scrivi SOLO il payload, niente testo extra."
    )


def prompt_feedback_attacco_con_judge(
    motivazione: str,
    tecnica_usata: str,
    suggerimento: str,
) -> str:
    """
    Feedback message for the red team enriched with judge analysis.

    Args:
        motivazione:   Judge's explanation of why the attack failed.
        tecnica_usata: Name/description of the SQLi technique detected.
        suggerimento:  Improvement suggestion from the judge.

    Returns:
        Formatted human message string to append to the conversation.
    """
    return (
        f"Il tuo attacco è fallito.\n\n"
        f"Analisi: {motivazione}\n"
        f"Tecnica rilevata: {tecnica_usata}\n"
        f"Suggerimento: {suggerimento}\n\n"
        "Genera un nuovo payload. Scrivi SOLO il payload."
    )


# ---------------------------------------------------------------------------
# Judge Attacco prompt
# ---------------------------------------------------------------------------

def prompt_judge_attacco(fatto: str, payload: str, risposta: str) -> str:
    """
    Prompt for the attack judge LLM.

    The judge receives the deterministic fact (successo/fallito) and must
    reason about *why*, providing technique identification and suggestions.
    The 'successo' field in the JSON output MUST be overridden by the caller
    with the ground-truth boolean — the LLM output is used for reasoning only.

    Args:
        fatto:    'SUCCESSO' or 'FALLITO' — established by node_esegui_attacco.
        payload:  The SQL injection payload that was sent.
        risposta: Cleaned HTTP response text (≤2000 chars).

    Returns:
        Formatted prompt string for the judge LLM.
    """
    return f"""Sei un esperto di sicurezza web che fa da arbitro in un esercizio su DVWA.

L'attacco ha avuto esito: {fatto}
Payload SQL Injection usato: {payload}
Risposta dell'applicazione (testo pulito): {risposta}

Restituisci SOLO un JSON (nessun testo prima o dopo):
{{
  "successo": {fatto.lower() == "successo"},
  "motivazione": "Spiegazione chiara del perché ha funzionato o fallito",
  "tecnica_usata": "Nome e descrizione della tecnica SQLi nel payload",
  "suggerimento": "Se fallito: cosa deve fare diversamente il red team. Se successo: cosa ha reso efficace l'attacco."
}}"""


# ---------------------------------------------------------------------------
# Blue Team prompts
# ---------------------------------------------------------------------------

BLUE_TEAM_SYSTEM = (
    "Sei un esperto di Secure Coding in PHP. Restituisci solo patch valide in formato Unified Diff."
)



def prompt_blue_team(
    codice_originale: str,
    payload: str,
    tecnica_usata: str,
) -> str:
    """
    Prompt for the blue team LLM (first attempt or after feedback).

    Args:
        codice_originale: The original vulnerable PHP source (never modified).
        payload:          The SQL injection payload that succeeded.
        tecnica_usata:    Technique name/description from the judge.

    Returns:
        Formatted human message string for the blue team LLM.
    """
    return (
        f"Codice vulnerabile:\n```php\n{codice_originale}\n```\n\n"
        f"Payload usato: {payload}. Tecnica: {tecnica_usata}.\n\n"
        "Correggi con prepared statements (PDO o MySQLi). "
        "Genera e restituisci una patch in formato Unified Diff standard (usando i prefissi --- low.php e +++ low.php). "
        "IMPORTANTE: Nel diff, mantieni ESATTAMENTE tutte le righe di contesto originali (inclusi tutti i commenti che iniziano con # o //, le righe vuote e gli spazi/tabulazioni originali). Non omettere MAI righe commentate (come quelle con #) o righe vuote se sono all'interno della sezione che stai modificando, altrimenti lo strumento `patch` fallirà a causa di conflitti. "
        "Scrivi SOLO il blocco di codice diff unificato (delimitato da ```diff), zero spiegazioni, zero testo extra."
    )


def prompt_feedback_patch(
    codice_originale: str,
    payload: str,
    tecnica_usata: str,
    problemi: str,
    motivazione: str,
) -> str:
    """
    Prompt for the blue team LLM after a failed patch attempt.

    Args:
        codice_originale: The original vulnerable PHP source (immutable).
        payload:          The SQL injection payload that still bypasses the patch.
        tecnica_usata:    Technique name/description from the attack judge.
        problemi:         List of problems identified by the patch judge.
        motivazione:      Patch judge's explanation of what went wrong.

    Returns:
        Formatted human message string for the blue team retry.
    """
    return (
        f"La tua patch precedente NON ha bloccato l'attacco oppure ha rotto le funzionalità legittime.\n\n"
        f"Problemi identificati: {problemi}\n"
        f"Motivazione: {motivazione}\n\n"
        f"Riparti dal codice originale vulnerabile:\n```php\n{codice_originale}\n```\n\n"
        f"Payload che ha bypassato la patch: {payload}. Tecnica: {tecnica_usata}.\n\n"
        "Correggi in modo più robusto con prepared statements (PDO o MySQLi). "
        "Genera una nuova patch in formato Unified Diff standard (usando i prefissi --- low.php e +++ low.php) che si applichi al codice originale. "
        "IMPORTANTE: Nel diff, mantieni ESATTAMENTE tutte le righe di contesto originali (inclusi tutti i commenti che iniziano con # o //, le righe vuote e gli spazi/tabulazioni originali). Non omettere MAI righe commentate (come quelle con #) o righe vuote se sono all'interno della sezione che stai modificando, altrimenti lo strumento `patch` fallirà a causa di conflitti. "
        "Scrivi SOLO il blocco di codice diff unificato (delimitato da ```diff), zero spiegazioni, zero testo extra."
    )


# ---------------------------------------------------------------------------
# Judge Patch prompt
# ---------------------------------------------------------------------------

def prompt_judge_patch(
    fatto: str,
    payload: str,
    risposta_post_patch: str,
    codice_patchato: str,
) -> str:
    """
    Prompt for the patch judge LLM.

    Similar to the attack judge: the caller forces the 'funzionale' boolean
    based on the deterministic HTTP check; the LLM evaluates code quality.

    Args:
        fatto:               'BLOCCATO (patch funzionale)' or 'PASSATO (patch non funzionale)'.
        payload:             The SQL injection payload used in the validation test.
        risposta_post_patch: Cleaned HTTP response after the patch was applied.
        codice_patchato:     The patched PHP source (≤3000 chars).

    Returns:
        Formatted prompt string for the patch judge LLM.
    """
    return f"""Sei un esperto di sicurezza web e secure coding che valuta una patch PHP su DVWA.

Esito del test post-patch: {fatto}
Payload testato: {payload}
Risposta applicazione dopo patch: {risposta_post_patch}
Codice patchato:
```php
{codice_patchato[:3000]}
```

Restituisci SOLO un JSON (nessun testo prima o dopo):
{{
  "funzionale": {fatto.startswith("BLOCCATO")},
  "qualita_codice": "ottima",
  "problemi": "nessuno",
  "motivazione": "Spiegazione: la patch blocca l'attacco? Il codice è scritto bene?"
}}

I valori di "qualita_codice" possibili sono: "ottima" | "sufficiente" | "insufficiente".
Sostituisci "nessuno" in "problemi" con un elenco reale se ne trovi."""
