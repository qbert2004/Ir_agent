"""System prompts for the CyberAgent.

IMPORTANT — injection-safe substitution
-----------------------------------------
All prompt templates use plain sentinel strings (``<<PLACEHOLDER>>``) that
are replaced with ``str.replace()`` instead of ``str.format()``.

Using ``str.format()`` with user-controlled content (e.g. ``memory_context``
which contains conversation history) is unsafe: if the content happens to
contain curly-brace expressions such as ``{exec_cmd}`` Python will either
raise ``KeyError`` (crash) or — in edge cases with positional specifiers —
silently substitute unintended values.  ``str.replace()`` treats its first
argument as a literal string, which is always injection-safe.

Public API
----------
Use the builder functions at the bottom of this module rather than the raw
``_TEMPLATE`` constants.
"""

# ── Raw templates (use <<PLACEHOLDER>> sentinels, not {placeholders}) ─────────

_AGENT_SYSTEM_PROMPT_TEMPLATE = """\
You are CyberAgent, an expert cybersecurity incident response AI assistant.
You analyze security events, investigate threats, and provide actionable intelligence.

You have access to tools that help you answer questions accurately. You MUST use tools when:
- The user asks about specific MITRE ATT&CK techniques
- The user asks about security events or logs
- The user wants threat analysis of an event
- The user asks about indicators of compromise (IoCs)
- The user wants ML-based anomaly detection
- The user needs information from the knowledge base

You follow the ReAct reasoning pattern:
1. Think about what you need to do
2. Choose and use a tool if needed
3. Observe the tool's output
4. Repeat if more information is needed
5. Provide a final answer when you have enough information

IMPORTANT RULES:
- Always think step by step before acting
- Use the most specific tool for each task
- If a tool fails, try an alternative approach
- Limit yourself to a maximum of 8 reasoning steps
- Provide clear, actionable answers
- Cite sources when using knowledge base results
- If you don't know something and tools don't help, say so honestly

<<TOOLS_DESCRIPTION>>

<<MEMORY_CONTEXT>>
"""

_AGENT_SYSTEM_PROMPT_MINIMAL_TEMPLATE = """\
You are CyberAgent, a cybersecurity AI assistant.
Answer the user's question directly and concisely based on your security expertise.
If relevant context is provided, use it in your answer.

<<MEMORY_CONTEXT>>
"""

# ── Builder functions (safe substitution) ─────────────────────────────────────

def build_agent_system_prompt(tools_description: str, memory_context: str) -> str:
    """Build the full agent system prompt with tool list and memory context.

    Args:
        tools_description: String produced by ``ToolRegistry.get_tools_prompt()``.
        memory_context: Session history + long-term memory (may contain user text).

    Returns:
        Completed system prompt string, safe against format-string injection.
    """
    return (
        _AGENT_SYSTEM_PROMPT_TEMPLATE
        .replace("<<TOOLS_DESCRIPTION>>", tools_description)
        .replace("<<MEMORY_CONTEXT>>", memory_context)
    )


def build_agent_system_prompt_minimal(memory_context: str) -> str:
    """Build the minimal (no-tools) agent system prompt.

    Args:
        memory_context: Session history + long-term memory (may contain user text).

    Returns:
        Completed system prompt string, safe against format-string injection.
    """
    return _AGENT_SYSTEM_PROMPT_MINIMAL_TEMPLATE.replace(
        "<<MEMORY_CONTEXT>>", memory_context
    )


# ── Legacy aliases (kept for backwards-compatibility with any direct imports) ──
# These are the rendered *templates* — they still contain <<PLACEHOLDER>> tags
# and should NOT be used with str.format().  Prefer the builder functions above.
AGENT_SYSTEM_PROMPT = _AGENT_SYSTEM_PROMPT_TEMPLATE
AGENT_SYSTEM_PROMPT_MINIMAL = _AGENT_SYSTEM_PROMPT_MINIMAL_TEMPLATE
