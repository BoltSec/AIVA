"""LangGraph pipeline: parser -> context -> exploitability -> prioritize -> recommend."""
from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from shared.models import Asset, Finding, RemediationPlan

from . import agents
from .clients import Intel, build_intel
from .llm import LLMReasoner, build_reasoner
from .plugin_map import PluginResolver, build_resolver

_AUTO = object()   # sentinel: auto-detect LLM from env (vs explicit None = off)


class PipelineState(TypedDict, total=False):
    xml: bytes
    source: str
    assets: list[Asset]
    findings: list[Finding]
    intel: Intel
    reasoner: LLMReasoner | None
    resolver: PluginResolver | None
    unresolved: int
    summary: str


def build_graph():
    g = StateGraph(PipelineState)
    g.add_node("parser", agents.parser_agent)
    g.add_node("resolver", agents.resolver_agent)
    g.add_node("context", agents.context_agent)
    g.add_node("exploitability", agents.exploitability_agent)
    g.add_node("prioritization", agents.prioritization_agent)
    g.add_node("recommendation", agents.recommendation_agent)
    g.add_node("summary", agents.summary_agent)

    g.set_entry_point("parser")
    g.add_edge("parser", "resolver")
    g.add_edge("resolver", "context")
    g.add_edge("context", "exploitability")
    g.add_edge("exploitability", "prioritization")
    g.add_edge("prioritization", "recommendation")
    g.add_edge("recommendation", "summary")
    g.add_edge("summary", END)
    return g.compile()


async def run_pipeline(
    xml_bytes: bytes,
    assets: list[Asset] | None = None,
    intel: Intel | None = None,
    source: str | None = None,
    reasoner=_AUTO,
    resolver=_AUTO,
) -> RemediationPlan:
    graph = build_graph()
    state: PipelineState = {
        "xml": xml_bytes,
        "assets": assets or [],
        "intel": intel or build_intel(),
        "reasoner": build_reasoner() if reasoner is _AUTO else reasoner,
        "resolver": build_resolver() if resolver is _AUTO else resolver,
    }
    if source:
        state["source"] = source
    result: dict[str, Any] = await graph.ainvoke(state)
    r = state.get("reasoner")
    if r is not None and hasattr(r, "flush"):
        r.flush()
    return RemediationPlan(
        scan_source=result.get("source", "unknown"),
        assets=assets or [],
        findings=result["findings"],
        summary=result.get("summary", ""),
    )
