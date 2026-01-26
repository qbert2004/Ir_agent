"""Base tool ABC, parameter/result models, and tool registry."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type


@dataclass
class ToolParameter:
    """Definition of a tool parameter."""
    name: str
    description: str
    type: str = "string"
    required: bool = True
    default: Any = None


@dataclass
class ToolResult:
    """Result of a tool execution."""
    success: bool
    output: str
    data: Optional[Dict] = None
    error: Optional[str] = None


class BaseTool(ABC):
    """Abstract base class for all agent tools."""

    name: str = ""
    description: str = ""
    parameters: List[ToolParameter] = []

    @abstractmethod
    def execute(self, **kwargs) -> ToolResult:
        """Execute the tool with given parameters.

        Args:
            **kwargs: Tool parameters as keyword arguments.

        Returns:
            ToolResult with success status and output.
        """
        ...

    def get_schema(self) -> Dict:
        """Return tool schema for the agent prompt."""
        params_desc = []
        for p in self.parameters:
            req = "(required)" if p.required else "(optional)"
            params_desc.append(f"  - {p.name} [{p.type}] {req}: {p.description}")

        return {
            "name": self.name,
            "description": self.description,
            "parameters": "\n".join(params_desc) if params_desc else "  None",
        }

    def validate_params(self, kwargs: Dict) -> Optional[str]:
        """Validate required parameters are present.

        Returns:
            Error message if validation fails, None otherwise.
        """
        for p in self.parameters:
            if p.required and p.name not in kwargs:
                return f"Missing required parameter: {p.name}"
        return None


class ToolRegistry:
    """Registry of available tools."""

    def __init__(self):
        self._tools: Dict[str, BaseTool] = {}

    def register(self, tool: BaseTool):
        """Register a tool instance."""
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[BaseTool]:
        """Get a tool by name."""
        return self._tools.get(name)

    def list_tools(self) -> List[BaseTool]:
        """List all registered tools."""
        return list(self._tools.values())

    def get_tools_prompt(self) -> str:
        """Generate tools description for the agent system prompt."""
        lines = ["Available Tools:"]
        for tool in self._tools.values():
            schema = tool.get_schema()
            lines.append(f"\n### {schema['name']}")
            lines.append(f"Description: {schema['description']}")
            lines.append(f"Parameters:\n{schema['parameters']}")
        return "\n".join(lines)

    def execute(self, tool_name: str, **kwargs) -> ToolResult:
        """Execute a tool by name.

        Args:
            tool_name: Name of the tool to execute.
            **kwargs: Tool parameters.

        Returns:
            ToolResult, or error result if tool not found.
        """
        tool = self.get(tool_name)
        if tool is None:
            return ToolResult(
                success=False,
                output="",
                error=f"Unknown tool: {tool_name}",
            )

        validation_error = tool.validate_params(kwargs)
        if validation_error:
            return ToolResult(
                success=False,
                output="",
                error=validation_error,
            )

        try:
            return tool.execute(**kwargs)
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=f"Tool execution error: {str(e)}",
            )
