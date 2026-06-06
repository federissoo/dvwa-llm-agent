"""
tests/test_judges.py — Unit tests for node_judge_attacco and node_judge_patch.

Run with:
    pytest tests/ -v

Tests use unittest.mock to isolate LLM calls so no API key is required.
All agent modules are imported at the top so @patch resolves correctly.
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure repo root is on sys.path so `agent` package resolves
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Provide a dummy OPENAI_API_KEY so langchain_openai doesn't raise at import time
os.environ.setdefault("OPENAI_API_KEY", "sk-test-placeholder-for-unit-tests")

# Module-level imports — required so @patch("agent.nodes.X") resolves correctly
import agent.nodes  # noqa: E402
from agent.nodes import (  # noqa: E402
    MAX_TENTATIVI_PATCH,
    decide_dopo_judge_patch,
    node_judge_attacco,
    node_judge_patch,
)


# ---------------------------------------------------------------------------
# Fixtures — minimal valid AgentState snapshots
# ---------------------------------------------------------------------------

def _base_state_attacco(attacco_successo: bool) -> dict:
    return {
        "messages": [],
        "tentativo": 1,
        "payload": "1' OR '1'='1",
        "risposta_http_raw": (
            "First name: admin Surname: admin "
            "First name: Gordon Surname: Brown"
        ),
        "attacco_successo": attacco_successo,
        "sessione_scaduta": False,
        "judge_attacco": {
            "successo": False,
            "motivazione": "",
            "tecnica_usata": "",
            "suggerimento": "",
        },
        "codice_originale": (
            "<?php $query = 'SELECT * FROM users WHERE user_id = '"
            " . $_GET['id']; ?>"
        ),
        "patch_applicata": False,
        "tentativo_patch": 0,
        "judge_patch": {
            "funzionale": False,
            "qualita_codice": "",
            "problemi": "",
            "motivazione": "",
        },
    }


def _base_state_patch(attacco_successo: bool, tentativo_patch: int = 0) -> dict:
    state = _base_state_attacco(attacco_successo=False)
    state["attacco_successo"] = attacco_successo
    state["tentativo_patch"] = tentativo_patch
    state["patch_applicata"] = True
    return state


def _make_mock_response(content: str) -> MagicMock:
    mock = MagicMock()
    mock.content = content
    return mock


# ---------------------------------------------------------------------------
# node_judge_attacco tests
# ---------------------------------------------------------------------------

class TestJudgeAttacco:
    """Tests for node_judge_attacco."""

    @patch.object(agent.nodes, "llm_judge")
    def test_judge_attacco_successo(self, mock_llm_judge):
        """LLM returns valid JSON with successo:true → judge_attacco.successo == True."""
        json_payload = json.dumps({
            "successo": True,
            "motivazione": "Il payload ha estratto tutti gli utenti.",
            "tecnica_usata": "UNION-based SQL Injection",
            "suggerimento": "Attacco efficace — nessuna modifica necessaria.",
        })
        mock_llm_judge.invoke.return_value = _make_mock_response(json_payload)

        state = _base_state_attacco(attacco_successo=True)
        result = node_judge_attacco(state)

        assert result["judge_attacco"]["successo"] is True
        assert result["judge_attacco"]["motivazione"] != ""
        assert result["judge_attacco"]["tecnica_usata"] != ""

    @patch.object(agent.nodes, "llm_judge")
    def test_judge_attacco_fallito(self, mock_llm_judge):
        """LLM returns valid JSON with successo:false → judge_attacco.successo == False."""
        json_payload = json.dumps({
            "successo": False,
            "motivazione": "Il payload non ha bypassato la query.",
            "tecnica_usata": "Boolean-based SQL Injection (fallita)",
            "suggerimento": "Prova una tecnica UNION SELECT.",
        })
        mock_llm_judge.invoke.return_value = _make_mock_response(json_payload)

        state = _base_state_attacco(attacco_successo=False)
        result = node_judge_attacco(state)

        assert result["judge_attacco"]["successo"] is False

    @patch.object(agent.nodes, "llm_judge")
    def test_judge_attacco_json_malformato(self, mock_llm_judge):
        """LLM returns non-JSON → fallback used, no exception raised.

        Ground-truth value of attacco_successo from input state must be
        preserved regardless of the LLM's garbled output.
        """
        mock_llm_judge.invoke.return_value = _make_mock_response(
            "Scusa, non posso elaborare questa richiesta in formato JSON."
        )

        state_true = _base_state_attacco(attacco_successo=True)
        result_true = node_judge_attacco(state_true)
        assert result_true["judge_attacco"]["successo"] is True, (
            "Ground truth (True) must survive malformed JSON fallback"
        )

        state_false = _base_state_attacco(attacco_successo=False)
        result_false = node_judge_attacco(state_false)
        assert result_false["judge_attacco"]["successo"] is False, (
            "Ground truth (False) must survive malformed JSON fallback"
        )

    @patch.object(agent.nodes, "llm_judge")
    def test_judge_attacco_ground_truth_override(self, mock_llm_judge):
        """LLM claims successo:True but HTTP ground truth is False → False wins."""
        json_payload = json.dumps({
            "successo": True,  # LLM incorrectly says True
            "motivazione": "Sembra che l'attacco abbia funzionato.",
            "tecnica_usata": "Boolean-based",
            "suggerimento": "Nessuno.",
        })
        mock_llm_judge.invoke.return_value = _make_mock_response(json_payload)

        state = _base_state_attacco(attacco_successo=False)  # HTTP said False
        result = node_judge_attacco(state)

        assert result["judge_attacco"]["successo"] is False, (
            "node_judge_attacco must force 'successo' from state['attacco_successo'], "
            "not from the LLM JSON"
        )


# ---------------------------------------------------------------------------
# node_judge_patch tests
# ---------------------------------------------------------------------------

class TestJudgePatch:
    """Tests for node_judge_patch."""

    @patch.object(agent.nodes, "PATH_FILE_VULNERABILE")
    @patch.object(agent.nodes, "llm_judge")
    def test_judge_patch_funzionale(self, mock_llm_judge, mock_path):
        """Patch blocks attack → patch_applicata=True, funzionale=True."""
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = (
            "<?php $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?'); ?>"
        )

        json_payload = json.dumps({
            "funzionale": True,
            "qualita_codice": "ottima",
            "problemi": "nessuno",
            "motivazione": "La patch usa prepared statements correttamente.",
        })
        mock_llm_judge.invoke.return_value = _make_mock_response(json_payload)

        # attacco_successo=False means the patch blocked the attack
        state = _base_state_patch(attacco_successo=False)
        result = node_judge_patch(state)

        assert result["judge_patch"]["funzionale"] is True
        assert result["patch_applicata"] is True

    @patch.object(agent.nodes, "PATH_FILE_VULNERABILE")
    @patch.object(agent.nodes, "llm_judge")
    def test_judge_patch_non_funzionale_riprova(self, mock_llm_judge, mock_path):
        """Patch failed + retries available → decide_dopo_judge_patch returns 'feedback_patch'."""
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = "<?php echo $_GET['id']; ?>"

        json_payload = json.dumps({
            "funzionale": False,
            "qualita_codice": "insufficiente",
            "problemi": "Nessun sanitization. Dati non validati.",
            "motivazione": "La patch non usa prepared statements.",
        })
        mock_llm_judge.invoke.return_value = _make_mock_response(json_payload)

        # attacco_successo=True means the patch failed
        state = _base_state_patch(attacco_successo=True, tentativo_patch=0)
        result = node_judge_patch(state)

        assert result["judge_patch"]["funzionale"] is False
        assert result["patch_applicata"] is False

        merged_state = {**state, **result}
        assert MAX_TENTATIVI_PATCH > 0, "MAX_TENTATIVI_PATCH must be > 0 for retry logic"
        routing = decide_dopo_judge_patch(merged_state)
        assert routing == "feedback_patch", (
            f"Expected 'feedback_patch' but got '{routing}'. "
            "With funzionale=False and tentativo_patch < MAX_TENTATIVI_PATCH, "
            "the graph should retry."
        )

    @patch.object(agent.nodes, "PATH_FILE_VULNERABILE")
    @patch.object(agent.nodes, "llm_judge")
    def test_judge_patch_non_funzionale_esaurito(self, mock_llm_judge, mock_path):
        """Patch failed + retries exhausted → decide_dopo_judge_patch returns END."""
        from langgraph.graph import END

        mock_path.exists.return_value = True
        mock_path.read_text.return_value = "<?php echo $_GET['id']; ?>"

        json_payload = json.dumps({
            "funzionale": False,
            "qualita_codice": "insufficiente",
            "problemi": "Sempre vulnerabile.",
            "motivazione": "Nessun miglioramento rispetto al tentativo precedente.",
        })
        mock_llm_judge.invoke.return_value = _make_mock_response(json_payload)

        state = _base_state_patch(
            attacco_successo=True,
            tentativo_patch=MAX_TENTATIVI_PATCH,  # retries exhausted
        )
        result = node_judge_patch(state)
        merged_state = {**state, **result}

        routing = decide_dopo_judge_patch(merged_state)
        assert routing == END, (
            f"Expected END but got '{routing}'. "
            "With tentativo_patch >= MAX_TENTATIVI_PATCH the graph must terminate."
        )

    @patch.object(agent.nodes, "PATH_FILE_VULNERABILE")
    @patch.object(agent.nodes, "llm_judge")
    def test_judge_patch_ground_truth_override(self, mock_llm_judge, mock_path):
        """LLM claims funzionale:False but HTTP says patch worked → True wins."""
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = "<?php $stmt = $pdo->prepare('?'); ?>"

        json_payload = json.dumps({
            "funzionale": False,  # LLM incorrectly disagrees
            "qualita_codice": "sufficiente",
            "problemi": "Potrebbe esserci un problema.",
            "motivazione": "Non sono sicuro che la patch funzioni.",
        })
        mock_llm_judge.invoke.return_value = _make_mock_response(json_payload)

        # HTTP says attack failed → patch worked
        state = _base_state_patch(attacco_successo=False)
        result = node_judge_patch(state)

        assert result["judge_patch"]["funzionale"] is True, (
            "node_judge_patch must force 'funzionale' from not(state['attacco_successo']), "
            "not from the LLM JSON"
        )
        assert result["patch_applicata"] is True
