from langgraph.types import Send
from typing import Annotated, List
import operator
from langgraph.graph import StateGraph, START, END
import mcp_caller
# Graph state
class State():
    attacks: List[str]
    gathered_attacks: Annotated[
        list, operator.add
    ]
    final_report: str

# Worker state
class WorkerState():
    attack_type: str
    gathered_attacks: Annotated[
        list, operator.add
    ] 

# Nodes
def orchestrator(state: State):

    # Generate queries
    # report_sections = planner.invoke(
    #     [
    #         SystemMessage(content="Generate a plan for the report."),
    #         HumanMessage(content=f"Here is the report topic: {state['topic']}"),
    #     ]
    # )

    return {"attacks": []}


def mcp_call(state: WorkerState):
    attacks = mcp_caller.call_mcp("get_techniques_by_tactic", {"tactic" : state["attack_type"], "include_description" : True})

    return {"gathered_attacks": [attacks[:5]]}


def synthesizer(state: State):
    gathered_attacks = state["gathered_attacks"]

    gathered_attacks_sections = "\n\n---\n\n".join(gathered_attacks)

    return {"final_report": gathered_attacks_sections}


def assign_workers(state: State):
    """Assign a worker to each section in the plan"""

    # Kick off writing in parallel via Send() API
    return [Send("mcp_call", {"attack": s}) for s in state["attacks"]]


# Build workflow
orchestrator_worker_builder = StateGraph(State)

# Add the nodes
orchestrator_worker_builder.add_node("orchestrator", orchestrator)
orchestrator_worker_builder.add_node("mcp_call", mcp_call)
orchestrator_worker_builder.add_node("synthesizer", synthesizer)

# Add edges to connect nodes
orchestrator_worker_builder.add_edge(START, "orchestrator")
orchestrator_worker_builder.add_conditional_edges(
    "orchestrator", assign_workers, ["mcp_call"]
)
orchestrator_worker_builder.add_edge("mcp_call", "synthesizer")
orchestrator_worker_builder.add_edge("synthesizer", END)

# Compile the workflow
orchestrator_worker = orchestrator_worker_builder.compile()

# # Show the workflow
# display(Image(orchestrator_worker.get_graph().draw_mermaid_png()))

# Invoke
state = orchestrator_worker.invoke({"topic": "Create a report on LLM scaling laws"})