# dvwa-llm-agent

![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)
![LangGraph](https://img.shields.io/badge/LangGraph-0.2%2B-green)
![LangSmith](https://img.shields.io/badge/LangSmith-Tracing-orange?logo=langchain)

Sistema multi-agente adversariale su DVWA (Damn Vulnerable Web Application) che automatizza cicli Red Team / Blue Team con reasoning LLM e giudici autonomi, costruito con LangGraph.

---

## Grafo del flusso

```mermaid
graph TD
    START --> init
    init -->|file OK| red_team
    init -->|file mancante| end_sessione --> END_ERR([END])

    red_team --> esegui_attacco
    esegui_attacco --> judge_attacco

    judge_attacco -->|sessione scaduta| end_sessione
    judge_attacco -->|successo| blue_team
    judge_attacco -->|fallito + feedback| feedback_attacco --> red_team
    judge_attacco -->|fallito + esaurito| END_A([END])

    blue_team -->|patch scritta| valida_patch
    blue_team -->|errore| END_B([END])

    valida_patch --> judge_patch

    judge_patch -->|patch OK| END_C([END])
    judge_patch -->|patch fallita + riprova| feedback_patch --> blue_team
    judge_patch -->|patch fallita + esaurito| END_D([END])
```

---

## Architettura — Nodi

| # | Nodo | Ruolo | LLM |
|---|------|-------|-----|
| 1 | `node_init` | Legge `low.php` dal disco e salva in stato; esce se il file manca | — |
| 2 | `node_red_team` | Genera payload SQL Injection iterativi | gpt-4o-mini |
| 3 | `node_esegui_attacco` | Invia il payload a DVWA via HTTP; conta `First name:` per determinare il fatto | — |
| 4 | `node_judge_attacco` | Ragiona sul perché l'attacco ha funzionato/fallito; fornisce tecnica e suggerimenti | gpt-4o |
| 5 | `node_feedback_attacco` | Inietta feedback del judge nello storico messaggi del red team | — |
| 6 | `node_blue_team` | Genera patch PHP con prepared statements partendo dal codice originale | gpt-4o-mini |
| 7 | `node_feedback_patch` | Inietta problemi rilevati dal judge nella prossima iterazione del blue team | — |
| 8 | `node_valida_patch` | Ri-esegue l'attacco sul codice patchato per verificare l'efficacia | — |
| 9 | `node_judge_patch` | Valuta qualità del codice patchato e conferma blocco dell'attacco | gpt-4o |

---

## Quickstart

```bash
# 1. Clona la repo
git clone https://github.com/<your-org>/dvwa-llm-agent.git
cd dvwa-llm-agent

# 2. Configura le credenziali
cp api_keys.env.example api_keys.env
# Modifica api_keys.env:
#   - OPENAI_API_KEY → chiave OpenAI
#   - PHPSESSID → cookie copiato dal browser dopo login su http://localhost:4280

# 3. Avvia DVWA
docker compose up -d

# 4. Esegui l'agente
python main.py
```

> **Login DVWA**: naviga su `http://localhost:4280`, accedi con `admin / password`,
> vai su *DVWA Security* → imposta **Low**, poi copia il cookie `PHPSESSID`
> da DevTools → Application → Cookies e incollalo in `api_keys.env`.

---

## Dipendenze

```bash
pip install -r requirements.txt
```

Richiede Python 3.11+.

---

## Test

```bash
pytest tests/ -v
```

I test non richiedono chiavi API — le chiamate LLM sono moccate con `unittest.mock`.

---

## LangSmith — Tracciamento

Con le variabili LangSmith configurate in `api_keys.env`, ogni run viene tracciata
automaticamente su [smith.langchain.com](https://smith.langchain.com):

```env
LANGCHAIN_TRACING_V2=true
LANGCHAIN_API_KEY=ls__...
LANGCHAIN_PROJECT=dvwa-llm-agent
```

Il tracciamento include ogni chiamata LLM, i token usati, la latenza e il grafo
di esecuzione completo. È fortemente consigliato per il debug e l'ottimizzazione
dei prompt.

---

## Struttura della repo

```
dvwa-llm-agent/
├── agent/
│   ├── __init__.py         # Package init
│   ├── state.py            # AgentState, JudgeAttaccoResult, JudgePatchResult
│   ├── prompts.py          # Tutte le stringhe di prompt come funzioni tipizzate
│   ├── nodes.py            # Tutti i nodi e le conditional edge functions
│   └── graph.py            # Costruzione e compilazione del grafo
├── tests/
│   └── test_judges.py      # Unit test per i due judge (pytest + mock)
├── main.py                 # Entrypoint CLI
├── docker-compose.yml      # Avvia DVWA su 127.0.0.1:4280
├── requirements.txt        # Dipendenze con versioni minime
├── api_keys.env.example    # Template variabili d'ambiente
└── README.md               # Questo file
```

---

## ⚠️ Disclaimer

> **Questo progetto è a scopo esclusivamente educativo.**
> DVWA è un'applicazione intenzionalmente vulnerabile progettata per l'apprendimento
> della sicurezza web in ambienti controllati.
> **Non esporre mai DVWA su reti pubbliche.**
> L'uso delle tecniche illustrate contro sistemi reali senza esplicita autorizzazione
> è illegale e contrario all'etica professionale.
