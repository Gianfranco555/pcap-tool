import openai
from unittest.mock import Mock, patch

from pcap_tool.llm_summarizer import LLMSummarizer


def test_generate_text_summary_basic():
    metrics = {"foo": "bar"}
    fake_response = Mock()
    fake_response.id = "abc123"
    fake_usage = Mock(total_tokens=5)
    fake_response.usage = fake_usage
    fake_response.choices = [Mock(message=Mock(content="the summary"))]

    client = openai.Client(api_key="test")
    summarizer = LLMSummarizer(client=client)

    with patch.object(client.chat.completions, "create", return_value=fake_response) as mock_create:
        result = summarizer.generate_text_summary(metrics)

    called_messages = mock_create.call_args.kwargs["messages"]
    assert "\"foo\": \"bar\"" in called_messages[1]["content"]
    assert result == "the summary"
