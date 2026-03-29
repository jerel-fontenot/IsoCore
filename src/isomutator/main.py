"""
ALGORITHM SUMMARY:
This is the IsoMutator Orchestrator. It manages the two-stage red-teaming pipeline.
It initializes the Attack Queue (for outgoing payloads) and the Eval Queue (for incoming target responses).
Currently, it boots the PromptMutator to flood the Attack Queue with fuzzy payloads.

TECHNOLOGY QUIRKS:
- Asyncio Task Management: The Mutator runs indefinitely in the main event loop. When Ctrl+C 
is pressed, the handle_shutdown algorithm cancels this task, raising a CancelledError which we catch cleanly to prevent ugly stack traces.
"""
import asyncio
import signal
import sys
import multiprocessing

from isomutator.core.queue_manager import QueueManager
from isomutator.core.log_manager import LogManager
from isomutator.core.config import settings
from isomutator.ingestors.mutator import PromptMutator
from isomutator.processors.striker import AsyncStriker
from isomutator.processors.judge import RedTeamJudge

# Global references for the shutdown handler
_queue_manager = None
_log_manager = None
_inference_workers = []
_system_logger = None
_shutdown_event = multiprocessing.Event()


def handle_shutdown(sig, frame):
    """The Graceful Shutdown Algorithm. Intercepts SIGINT (Ctrl+C)."""
    print("\n[Orchestrator] Shutdown signal received (Ctrl+C).")
    if _system_logger:
        _system_logger.info("Commencing safe teardown...")

    # 1. Stop the Scrapers
    try:
        loop = asyncio.get_running_loop()
        for task in asyncio.all_tasks(loop):
            if task is not asyncio.current_task(loop):
                task.cancel()
    except RuntimeError:
        pass # Loop might already be closed

    # 2. Engage the Emergency Stop
    if _system_logger:
        _system_logger.info("Engaging Emergency Stop Event. Bypassing queue...")
    _shutdown_event.set()

    # 3. Wait for the fleet to finish their current batch and exit
    if _inference_workers:
        if _system_logger:
            _system_logger.info(f"Waiting for {len(_inference_workers)} workers to finish current batch...")
        for worker in _inference_workers:
            if worker.is_alive():
                worker.join(timeout=settings.shutdown_timeout)
                if worker.is_alive():
                    if _system_logger:
                        _system_logger.warning(f"{worker.name} stuck. Terminating forcefully.")
                    worker.terminate()

    # 4. Stop the Heart
    if _queue_manager:
        _queue_manager.close()

    # 5. Flush the Logs
    if _log_manager:
        if _system_logger:
            _system_logger.info("Flushing remaining logs to disk...")
        _log_manager.stop()

    print("--- isomutator Shutdown Complete ---")
    sys.exit(0)


async def boot_sequence():
    """The Boot Sequence Algorithm."""
    global _attack_queue, _eval_queue, _system_logger, _inference_workers

    _system_logger.info("IsoMutator Boot Sequence Initiated.")
    
    # 1. Boot the Two-Stage Queues
    _attack_queue = QueueManager(max_size=1000)
    _eval_queue = QueueManager(max_size=1000)

    # 2. Boot the Red Team Judge (The Scorer)
    judge = RedTeamJudge(
        eval_queue=_eval_queue,
        log_queue=_log_manager.log_queue
    )
    judge.start()
    _inference_workers.append(judge)

    # 3. Boot the Async Striker (The Outbound Cannon)
    striker = AsyncStriker(
        attack_queue=_attack_queue,
        eval_queue=_eval_queue,
        log_queue=_log_manager.log_queue,
        # Pointing to the remote Ollama daemon's chat endpoint
        target_url="http://192.9.159.125:11434/api/chat" 
    )
    striker.start()
    
    # Add the striker to the workers list so it receives the poison pill on shutdown
    _inference_workers.append(striker) 

    # 4. Boot the Payload Generator
    mutator = PromptMutator(_attack_queue)
    _system_logger.info("Starting Asynchronous Prompt Mutator...")
    
    try:
        await mutator.listen()
    except asyncio.CancelledError:
        _system_logger.trace("Main event loop caught CancelledError. Shutting down generator.")


def main():
    """Entry point for isomutator."""
    print("--- Starting isomutator ---")
    print("Press Ctrl+C to stop.")

    # Force "spawn" to prevent async/fork deadlocks on Linux
    multiprocessing.set_start_method("spawn", force=True)
    
    # Boot the logging bridge outside the async loop
    global _log_manager, _system_logger
    try:
        _log_manager = LogManager()
        _log_manager.start()
        _system_logger = LogManager.get_logger("isomutator.system")
    except Exception as e:
        print(f"CRITICAL ERROR: Failed to boot LogManager. Check your JSON path. Details: {e}")
        sys.exit(1)

    # Start the async environment
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.add_signal_handler(signal.SIGINT, lambda: handle_shutdown(signal.SIGINT, None))
    
    try:
        loop.run_until_complete(boot_sequence())
    finally:
        loop.close()


if __name__ == "__main__":
    main()