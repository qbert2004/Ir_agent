"""CyberAgent - ReAct reasoning loop with tools, memory, and RAG."""

import uuid
import logging
from typing import Optional

from app.agent.core.reasoning import parse_llm_output, format_observation
from app.agent.memory.memory_manager import MemoryManager
from app.agent.prompts.system_prompts import AGENT_SYSTEM_PROMPT, AGENT_SYSTEM_PROMPT_MINIMAL
from app.agent.prompts.react_templates import (
    REACT_INSTRUCTION,
    USER_QUERY_TEMPLATE,
    CONTINUATION_TEMPLATE,
)
from app.agent.schemas import AgentResponse, AgentStep
from app.agent.tools.base import ToolRegistry

logger = logging.getLogger(__name__)

MAX_STEPS = 8


class CyberAgent:
    """ReAct-based cybersecurity agent with tools, memory, and RAG."""

    def __init__(self, tool_registry: ToolRegistry, memory_manager: MemoryManager):
        self.tools = tool_registry
        self.memory = memory_manager

    def run(self, query: str, session_id: Optional[str] = None) -> AgentResponse:
        """Execute the agent's ReAct loop for a given query.

        Args:
            query: User's question or task.
            session_id: Session ID for memory continuity.

        Returns:
            AgentResponse with answer, steps, and tools used.
        """
        if not session_id:
            session_id = uuid.uuid4().hex[:12]

        # Record user message in memory
        self.memory.add_user_message(session_id, query)

        # Build context from memory
        memory_context = self.memory.get_context(session_id, query)

        # Determine if tools are needed (simple heuristic)
        tools_description = self.tools.get_tools_prompt()
        has_tools = bool(self.tools.list_tools())

        if not has_tools:
            # No tools available - direct answer
            answer = self._call_llm_direct(query, memory_context)
            self.memory.add_assistant_message(session_id, answer)
            return AgentResponse(
                answer=answer,
                steps=[],
                tools_used=[],
                total_steps=0,
                session_id=session_id,
            )

        # Build system prompt
        system_prompt = AGENT_SYSTEM_PROMPT.format(
            tools_description=tools_description,
            memory_context=memory_context,
        )

        # Build initial user prompt with ReAct instruction
        user_prompt = USER_QUERY_TEMPLATE.format(
            react_instruction=REACT_INSTRUCTION,
            query=query,
        )

        steps = []
        tools_used = []
        accumulated_context = ""

        for step_num in range(1, MAX_STEPS + 1):
            # Call LLM
            if step_num == 1:
                llm_input = user_prompt
            else:
                llm_input = CONTINUATION_TEMPLATE.format(
                    previous_steps=accumulated_context,
                    observation=steps[-1].observation or "",
                )

            raw_output = self._call_llm(system_prompt, llm_input)

            # Parse the output
            parsed = parse_llm_output(raw_output)

            # Create step record
            step = AgentStep(
                step_number=step_num,
                thought=parsed.thought,
                action=parsed.action,
                action_input=parsed.action_input,
                is_final=parsed.final_answer is not None,
            )

            # If final answer, we're done
            if parsed.final_answer:
                step.is_final = True
                steps.append(step)

                answer = parsed.final_answer
                self.memory.add_assistant_message(session_id, answer)

                # Store significant findings in long-term memory
                if tools_used:
                    self.memory.store_investigation(
                        f"Query: {query}\nAnswer: {answer[:500]}",
                        session_id=session_id,
                        metadata={"tools_used": tools_used},
                    )

                return AgentResponse(
                    answer=answer,
                    steps=steps,
                    tools_used=tools_used,
                    total_steps=step_num,
                    session_id=session_id,
                )

            # Execute tool if action specified
            if parsed.action:
                tool_result = self.tools.execute(parsed.action, **parsed.action_input)
                observation = tool_result.output if tool_result.success else f"Error: {tool_result.error}"
                step.observation = observation

                if parsed.action not in tools_used:
                    tools_used.append(parsed.action)

                # Build accumulated context
                accumulated_context += f"\nThought: {parsed.thought}\n"
                accumulated_context += f"Action: {parsed.action}\n"
                accumulated_context += f"Action Input: {self._format_params(parsed.action_input)}\n"
                accumulated_context += format_observation(observation)
            else:
                # No action and no final answer - force a final answer
                step.observation = "No action specified. Providing direct answer."
                step.is_final = True
                steps.append(step)

                answer = parsed.thought or raw_output.strip()
                self.memory.add_assistant_message(session_id, answer)
                return AgentResponse(
                    answer=answer,
                    steps=steps,
                    tools_used=tools_used,
                    total_steps=step_num,
                    session_id=session_id,
                )

            steps.append(step)

        # Max steps reached - synthesize final answer
        answer = self._synthesize_final_answer(query, steps, system_prompt)
        self.memory.add_assistant_message(session_id, answer)

        if tools_used:
            self.memory.store_investigation(
                f"Query: {query}\nAnswer: {answer[:500]}",
                session_id=session_id,
                metadata={"tools_used": tools_used},
            )

        return AgentResponse(
            answer=answer,
            steps=steps,
            tools_used=tools_used,
            total_steps=MAX_STEPS,
            session_id=session_id,
        )

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Call the Groq LLM with system and user prompts."""
        try:
            from groq import Groq
            import os

            api_key = os.getenv("LLM_API_KEY") or os.getenv("GROQ_API_KEY")
            model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

            if not api_key:
                return "Final Answer: LLM API key not configured. Cannot process query."

            client = Groq(api_key=api_key)
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.2,
                max_tokens=1024,
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return f"Final Answer: Error calling LLM: {str(e)}"

    def _call_llm_direct(self, query: str, memory_context: str) -> str:
        """Call LLM directly without ReAct (for simple queries with no tools)."""
        system = AGENT_SYSTEM_PROMPT_MINIMAL.format(memory_context=memory_context)
        return self._call_llm(system, query)

    def _synthesize_final_answer(self, query: str, steps: list, system_prompt: str) -> str:
        """Synthesize a final answer from accumulated observations when max steps reached."""
        observations = []
        for s in steps:
            if s.observation:
                observations.append(s.observation[:500])

        synthesis_prompt = (
            f"Based on the following observations gathered while investigating the query, "
            f"provide a comprehensive final answer.\n\n"
            f"Query: {query}\n\n"
            f"Gathered Information:\n" + "\n---\n".join(observations) +
            f"\n\nProvide your final answer:"
        )

        result = self._call_llm(system_prompt, synthesis_prompt)

        # Extract just the answer part
        parsed = parse_llm_output(result)
        return parsed.final_answer or parsed.thought or result.strip()

    def _format_params(self, params: dict) -> str:
        """Format parameters dict for context."""
        return "\n".join(f"{k}={v}" for k, v in params.items())
