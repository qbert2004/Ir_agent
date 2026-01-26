"""Output parser for ReAct reasoning (Thought/Action/Observation extraction)."""

import re
from typing import Dict

from app.agent.schemas import ThoughtAction


def parse_llm_output(text: str) -> ThoughtAction:
    """Parse LLM output into structured ThoughtAction.

    Extracts Thought, Action, Action Input, and Final Answer from
    the ReAct-formatted LLM response.

    Args:
        text: Raw LLM output text.

    Returns:
        ThoughtAction with parsed fields.
    """
    result = ThoughtAction(raw_output=text)

    # Extract Thought
    thought_match = re.search(
        r"Thought:\s*(.+?)(?=\n(?:Action|Final Answer):|\Z)",
        text,
        re.DOTALL,
    )
    if thought_match:
        result.thought = thought_match.group(1).strip()

    # Check for Final Answer first
    final_match = re.search(
        r"Final Answer:\s*(.+)",
        text,
        re.DOTALL,
    )
    if final_match:
        result.final_answer = final_match.group(1).strip()
        return result

    # Extract Action
    action_match = re.search(
        r"Action:\s*(\S+)",
        text,
    )
    if action_match:
        result.action = action_match.group(1).strip()

    # Extract Action Input
    input_match = re.search(
        r"Action Input:\s*(.+?)(?=\n(?:Thought|Action|Observation|Final Answer):|\Z)",
        text,
        re.DOTALL,
    )
    if input_match:
        raw_input = input_match.group(1).strip()
        result.action_input = _parse_action_input(raw_input)

    # If no structured output found, treat entire text as final answer
    if not result.thought and not result.action and not result.final_answer:
        result.final_answer = text.strip()

    return result


def _parse_action_input(raw: str) -> Dict[str, str]:
    """Parse action input from key=value format.

    Supports:
      key=value (one per line)
      key: value (one per line)
      single value (assigned to 'query' or first param)

    Args:
        raw: Raw action input string.

    Returns:
        Dict of parameter name -> value.
    """
    params = {}

    lines = [l.strip() for l in raw.split("\n") if l.strip()]

    for line in lines:
        # Try key=value format
        eq_match = re.match(r"(\w+)\s*=\s*(.+)", line)
        if eq_match:
            key = eq_match.group(1)
            value = eq_match.group(2).strip().strip("\"'")
            params[key] = value
            continue

        # Try key: value format
        colon_match = re.match(r"(\w+)\s*:\s*(.+)", line)
        if colon_match:
            key = colon_match.group(1)
            value = colon_match.group(2).strip().strip("\"'")
            params[key] = value
            continue

    # If no key-value pairs found, use the whole input as 'query'
    if not params and raw.strip():
        params["query"] = raw.strip().strip("\"'")

    return params


def format_observation(text: str, max_chars: int = 2000) -> str:
    """Format and truncate an observation for the next prompt.

    Args:
        text: Raw observation text.
        max_chars: Maximum characters to include.

    Returns:
        Formatted observation string.
    """
    if len(text) > max_chars:
        text = text[:max_chars] + "\n... [truncated]"
    return f"Observation: {text}"
