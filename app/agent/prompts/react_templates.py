"""ReAct format templates for the agent reasoning loop."""

REACT_INSTRUCTION = """
To use a tool, you MUST use exactly this format:

Thought: [Your reasoning about what to do next]
Action: [tool_name]
Action Input: [input parameters as key=value, one per line]

After receiving an observation, continue with another Thought/Action or give a final answer:

Thought: [Your reasoning based on the observation]
Final Answer: [Your complete answer to the user's question]

IMPORTANT:
- Always start with a Thought
- Use exactly one Action per step
- Action Input parameters: one per line, format: key=value
- End with "Final Answer:" when you have enough information
- Do NOT make up information - use tools to verify
"""

REACT_STEP_FORMAT = """
Thought: {thought}
Action: {action}
Action Input: {action_input}
"""

REACT_OBSERVATION_FORMAT = """
Observation: {observation}
"""

REACT_FINAL_FORMAT = """
Thought: {thought}
Final Answer: {answer}
"""

USER_QUERY_TEMPLATE = """
{react_instruction}

User Question: {query}

Begin your reasoning:
"""

CONTINUATION_TEMPLATE = """
{previous_steps}

{observation}

Continue your reasoning (remember: Thought -> Action or Final Answer):
"""
