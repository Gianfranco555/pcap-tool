"""LLM-based summarizer for metrics."""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Optional
from pathlib import Path

import openai

logger = logging.getLogger(__name__)


class LLMSummarizerError(Exception):
    """Raised when LLM summarization fails."""


class LLMSummarizer:
    """Generate plain-English summaries of metrics via GPT."""

    def __init__(self, client: Optional[openai.Client] = None, model: str = "gpt-4o") -> None:
        """Initialize the summarizer with an optional OpenAI client."""
        if client is None:
            api_key = os.environ.get("OPENAI_API_KEY")
            client = openai.Client(api_key=api_key)
        self.client = client
        self.model = model

    def generate_text_summary(
        self,
        metrics_json: dict,
        *,
        temperature: float = 0.3,
        max_tokens: int = 800,
    ) -> str:
        """Return a plain-English summary of ``metrics_json`` using GPT."""
        payload = json.dumps(metrics_json, indent=2)
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a senior network-operations analyst. "
                    "Return a concise plain-English summary of the supplied metrics. "
                    "Highlight key patterns, potential issues, and actionable insights. "
                    "Use short paragraphs and bullet lists where helpful. "
                    "Do not invent metrics that are not present."
                ),
            },
            {"role": "user", "content": f"Here is the metrics payload:\n```json\n{payload}\n```"},
        ]

        for attempt in range(3):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    timeout=30,
                )
                logger.debug(
                    "LLM summary request id=%s tokens=%s",
                    response.id,
                    response.usage.total_tokens,
                )
                return response.choices[0].message.content.strip()
            except (openai.RateLimitError, TimeoutError, openai.APIError) as exc:
                if attempt == 2:
                    raise LLMSummarizerError(str(exc)) from exc
                time.sleep(2 ** attempt)

        raise LLMSummarizerError("Failed to generate summary")


if __name__ == "__main__":

    sample = json.loads(Path("examples/metrics_sample.json").read_text())
    print(LLMSummarizer().generate_text_summary(sample))
