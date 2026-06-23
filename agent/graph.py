"""
agent/graph.py — LangGraph graph definition and compilation.

Assembles all nodes and edges into a compiled StateGraph.
Import `graph` from this module in main.py.

Graph topology:
    START
      └─► node_init ──► [file missing?] ──► end_sessione ──► END
                    └─► red_team ──► esegui_attacco ──► judge_attacco
                                                              ├─► [sessione scaduta] ──► end_sessione ──► END
                                                              ├─► [successo] ──► blue_team ──► valida_patch ──► judge_patch
                                                              │                                  ↑                    │
                                                              │                       feedback_patch ◄── [patch fallita, riprova]
                                                              │                                                       │
                                                              │                                               [fine] ──► END
                                                              ├─► [fallito, feedback] ──► feedback_attacco ──► red_team
                                                              └─► [fallito, esaurito] ──► END
"""

from langgraph.graph import END, START, StateGraph

from agent.nodes import (
    decide_dopo_blue_team,
    decide_dopo_init,
    decide_dopo_judge_attacco,
    decide_dopo_judge_patch,
    node_blue_team,
    node_esegui_attacco,
    node_feedback_attacco,
    node_feedback_patch,
    node_init,
    node_judge_attacco,
    node_judge_patch,
    node_red_team,
    node_valida_patch,
)
from agent.state import AgentState


def _end_sessione(state: AgentState) -> dict:
    """Terminal node — prints a clear error and exits the graph cleanly."""
    msg = state.get("risposta_http_raw", "Sessione scaduta o file non trovato.")
    print(f"\n🛑 [FINE] Terminazione forzata: {msg}")
    print("   → Verifica che DVWA sia raggiungibile e che il login automatico funzioni.")
    return {}


def build_graph() -> StateGraph:
    """
    Build and compile the full DVWA multi-agent LangGraph.

    Returns:
        Compiled StateGraph ready for .invoke() / .stream().
    """
    builder = StateGraph(AgentState)

    # ── Nodes ────────────────────────────────────────────────────────────────
    builder.add_node("init", node_init)
    builder.add_node("end_sessione", _end_sessione)
    builder.add_node("red_team", node_red_team)
    builder.add_node("esegui_attacco", node_esegui_attacco)
    builder.add_node("judge_attacco", node_judge_attacco)
    builder.add_node("feedback_attacco", node_feedback_attacco)
    builder.add_node("blue_team", node_blue_team)
    builder.add_node("valida_patch", node_valida_patch)
    builder.add_node("judge_patch", node_judge_patch)
    builder.add_node("feedback_patch", node_feedback_patch)

    # ── Edges ────────────────────────────────────────────────────────────────
    builder.add_edge(START, "init")

    builder.add_conditional_edges(
        "init",
        decide_dopo_init,
        {"end_sessione": "end_sessione", "red_team": "red_team"},
    )

    builder.add_edge("end_sessione", END)

    builder.add_edge("red_team", "esegui_attacco")
    builder.add_edge("esegui_attacco", "judge_attacco")

    builder.add_conditional_edges(
        "judge_attacco",
        decide_dopo_judge_attacco,
        {
            "end_sessione": "end_sessione",
            "blue_team": "blue_team",
            "feedback_attacco": "feedback_attacco",
            END: END,
        },
    )

    builder.add_edge("feedback_attacco", "red_team")

    builder.add_conditional_edges(
        "blue_team",
        decide_dopo_blue_team,
        {"valida_patch": "valida_patch", END: END},
    )

    builder.add_edge("valida_patch", "judge_patch")

    builder.add_conditional_edges(
        "judge_patch",
        decide_dopo_judge_patch,
        {"feedback_patch": "feedback_patch", END: END},
    )

    builder.add_edge("feedback_patch", "blue_team")

    return builder.compile()


# Module-level compiled graph — importable directly
graph = build_graph()
