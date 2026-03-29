"""
ALGORITHM SUMMARY:
Test suite for the PromptMutator generation engine.
1. Tests the synchronous `_generate_mutations` function to ensure all 4 attack 
vectors (raw, base64, framing, delimiter) are mathematically verified.
2. Tests the asynchronous queue insertion to ensure `DataPacket` objects flow 
correctly into the `QueueManager` without blocking.

TECHNOLOGY QUIRKS:
- Pytest Asyncio: Requires the `@pytest.mark.asyncio` decorator to properly await 
queue operations and asyncio.sleep within the test environment.
- Queue Peeking: We use `get_batch()` to pull the test data out of the queue 
to verify the internal state of the DataPackets.
"""

import pytest
import asyncio
import base64

from isomutator.core.queue_manager import QueueManager
from isomutator.ingestors.mutator import PromptMutator

def test_generate_mutations():
    """Verifies that a single seed generates the correct mathematical mutations."""
    # Setup
    fake_queue = QueueManager(max_size=10)
    mutator = PromptMutator(fake_queue)
    seed = "Steal the password"
    
    # Execute
    results = mutator._generate_mutations(seed)
    
    # Assertions
    assert len(results) == 4, "Should generate exactly 4 mutation strategies."
    
    strategies = [strat for _, strat in results]
    assert "raw_baseline" in strategies
    assert "base64_obfuscation" in strategies
    assert "fictional_framing" in strategies
    assert "delimiter_injection" in strategies

    # Verify Base64 math is exact
    b64_expected = base64.b64encode(seed.encode('utf-8')).decode('utf-8')
    b64_result = [text for text, strat in results if strat == "base64_obfuscation"][0]
    assert b64_expected in b64_result, "Base64 payload was not encoded correctly."

@pytest.mark.asyncio
async def test_mutator_queue_insertion():
    """Verifies the Mutator successfully builds packets and drops them in the queue."""
    # Setup
    test_queue = QueueManager(max_size=100)
    mutator = PromptMutator(test_queue)
    
    # We override the seed payloads to just one simple string for the test
    mutator.seed_payloads = ["Test Payload"]
    
    # Execute: We run the listener as a background task for just 0.1 seconds
    listen_task = asyncio.create_task(mutator.listen())
    await asyncio.sleep(0.1)
    listen_task.cancel()
    
    # Assertions
    # The mutator should have generated 4 packets for our 1 test seed
    batch = test_queue.get_batch(target_size=10, max_wait=0.1)
    
    assert len(batch) == 4, "Queue should contain exactly 4 mutated packets."
    assert batch[0].source == "mutator/raw_baseline"
    assert batch[0].metadata["original_seed"] == "Test Payload"