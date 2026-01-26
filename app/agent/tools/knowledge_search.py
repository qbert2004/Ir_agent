"""RAG knowledge search tool."""

from app.agent.tools.base import BaseTool, ToolParameter, ToolResult


class KnowledgeSearchTool(BaseTool):
    """Search the knowledge base for relevant security information."""

    name = "knowledge_search"
    description = (
        "Search the cybersecurity knowledge base (MITRE ATT&CK, NIST playbooks, "
        "attack patterns) for relevant information. Use this when you need reference "
        "material about threats, techniques, or incident response procedures."
    )
    parameters = [
        ToolParameter(
            name="query",
            description="Search query describing what information you need",
            type="string",
            required=True,
        ),
        ToolParameter(
            name="top_k",
            description="Number of results to return (default: 5)",
            type="integer",
            required=False,
            default=5,
        ),
    ]

    def __init__(self, retriever):
        self._retriever = retriever

    def execute(self, **kwargs) -> ToolResult:
        query = kwargs.get("query", "")
        top_k = int(kwargs.get("top_k", 5))

        if not query:
            return ToolResult(success=False, output="", error="Query cannot be empty")

        result_text = self._retriever.retrieve_formatted(query, top_k=top_k)

        return ToolResult(
            success=True,
            output=result_text,
            data={"query": query, "top_k": top_k},
        )
