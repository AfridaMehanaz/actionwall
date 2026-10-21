"""Wrap any Python function an agent can call (LangChain, LangGraph, OpenAI or Anthropic tool use)."""

from __future__ import annotations

import functools
from typing import Any, Callable, TypeVar

from .actions import Action, ActionBlocked, Kind
from .executor import tool_payload
from .guard import Guard

F = TypeVar("F", bound=Callable[..., Any])


def guarded(guard: Guard, name: str | None = None, on_block: str = "raise") -> Callable[[F], F]:
    """Decorator: check the call against tool policy and taint, then observe the result.

    on_block="raise" raises ActionBlocked; on_block="return" returns the reason as a string,
    which is usually what you want inside an agent loop so the model sees why it was stopped.
    """

    def wrap(fn: F) -> F:
        tool_name = name or fn.__name__

        @functools.wraps(fn)
        def inner(*args, **kwargs):
            action = Action(Kind.TOOL, tool_name, tool_payload(args, kwargs))
            decision = guard.check(action)
            if not decision.allowed:
                if on_block == "return":
                    return f"BLOCKED by actionwall: {decision.reason}"
                raise ActionBlocked(action, decision)
            result = fn(*args, **kwargs)
            guard.observe(action, str(result))
            return result

        return inner  # type: ignore[return-value]

    return wrap
