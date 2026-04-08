"""
ALGORITHM SUMMARY:
Validates the JSON ingestion hardening within the PromptMutator.
1. Happy Path: Clean JSON parsing passes without retries.
2. Markdown Stripping: Removing markdown formatting blocks using Regex.
3. Edge Cases/Retry Loop: Simulating a JSONDecodeError on the first API call, 
   verifying the Mutator appends the error, and succeeds on the second call.
4. Error Handling: Verifying graceful failure when retries are exhausted.

TECHNOLOGY QUIRKS:
- Mocking aiohttp: `aiohttp.ClientSession.post` is synchronous but returns an async 
  context manager. Therefore, `mock_session` must be a standard `MagicMock` rather 
  than an `AsyncMock`, so `.post()` returns the context manager immediately rather 
  than returning a coroutine.
"""

import json
import pytest
from unittest.mock import MagicMock

from isomutator.core.strategies import JailbreakStrategy
from isomutator.ingestors.mutator import PromptMutator

@pytest.fixture
def mutator_setup():
    strategy = JailbreakStrategy()
    # Mocking the multiprocessing queues as they aren't needed for this unit test
    mutator = PromptMutator(MagicMock(), MagicMock(), strategy)
    return mutator

class MockResponse:
    """Helper class to mock aiohttp async context managers."""
    def __init__(self, text, status=200):
        self._text = text
        self.status = status

    async def json(self):
        return {"message": {"content": self._text}}
        
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

@pytest.mark.asyncio
async def test_happy_path_json(mutator_setup):
    """Test that perfectly formatted JSON passes right through."""
    raw_llm_output = '{"attacks": [{"strategy": "test", "prompt": "clean json"}]}'
    
    # FIX: Use MagicMock so .post() behaves synchronously and returns the MockResponse context manager
    mock_session = MagicMock()
    mock_session.post.return_value = MockResponse(raw_llm_output)
    
    messages = [{"role": "user", "content": "test"}]
    result = await mutator_setup._call_llm_with_retry(mock_session, messages)
    
    assert "attacks" in result
    assert result["attacks"][0]["prompt"] == "clean json"
    assert mock_session.post.call_count == 1

@pytest.mark.asyncio
async def test_strip_markdown_json(mutator_setup):
    """Test that the regex correctly strips Markdown formatting."""
    md_ticks = chr(96) * 3
    # Use f-string to safely inject the backticks into the mock payload
    raw_llm_output = f'''{md_ticks}json
    {{
        "attacks": [{{"strategy": "test", "prompt": "markdown stripped"}}]
    }}
    {md_ticks}'''
    
    # FIX: Use MagicMock
    mock_session = MagicMock()
    mock_session.post.return_value = MockResponse(raw_llm_output)
    
    messages = [{"role": "user", "content": "test"}]
    result = await mutator_setup._call_llm_with_retry(mock_session, messages)
    
    assert "attacks" in result
    assert result["attacks"][0]["prompt"] == "markdown stripped"
    assert mock_session.post.call_count == 1

@pytest.mark.asyncio
async def test_retry_loop_on_bad_json(mutator_setup):
    """Test the LLM feedback loop when JSON parsing fails initially."""
    bad_output = '{ "attacks": [{"strategy": "test", "prompt": "missing quote} ] }'
    good_output = '{"attacks": [{"strategy": "test", "prompt": "fixed quote"}]}'
    
    # FIX: Use MagicMock
    mock_session = MagicMock()
    # The side_effect list lets us return different responses on subsequent calls
    mock_session.post.side_effect = [
        MockResponse(bad_output),
        MockResponse(good_output)
    ]
    
    messages = [{"role": "user", "content": "test"}]
    result = await mutator_setup._call_llm_with_retry(mock_session, messages)
    
    assert "attacks" in result
    assert result["attacks"][0]["prompt"] == "fixed quote"
    # Verify the loop actually ran twice
    assert mock_session.post.call_count == 2
    
    # Extract the payload sent on the second call to verify the error was appended
    second_call_kwargs = mock_session.post.call_args_list[1].kwargs
    second_call_messages = second_call_kwargs['json']['messages']
    
    assert len(second_call_messages) == 3 
    assert second_call_messages[1]["role"] == "assistant"
    assert "JSON parsing with error" in second_call_messages[2]["content"]

@pytest.mark.asyncio
async def test_exhaust_retries(mutator_setup):
    """Test that the system fails gracefully if the LLM refuses to output valid JSON."""
    bad_output = 'Just conversation, no json here.'
    
    # FIX: Use MagicMock
    mock_session = MagicMock()
    mock_session.post.return_value = MockResponse(bad_output)
    
    messages = [{"role": "user", "content": "test"}]
    result = await mutator_setup._call_llm_with_retry(mock_session, messages, max_retries=3)
    
    assert result == {}
    assert mock_session.post.call_count == 3