"""
IsoCore Orchestrator (src/isocore/main.py)
------------------------------------------
The "Conductor" of the IsoCore neural network project.
Run with: uv run python src/isocore/main.py
"""

import asyncio
import signal
import sys
import multiprocessing

# Core Managers
from isocore.core.log_manager import LogManager
from isocore.core.queue_manager import QueueManager

# Processors & Ingestors
from isocore.processors.inference import InferenceWorker
from isocore.ingestors.reddit import SimulatedRedditSource
from isocore.core.config import settings
from isocore.ingestors.hackernews_live import LiveHackerNewsSource

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

    print("--- IsoCore Shutdown Complete ---")
    sys.exit(0)


async def boot_sequence():
    """The Boot Sequence Algorithm."""
    global _queue_manager, _inference_worker, _system_logger

    _system_logger.info("IsoCore Boot Sequence Initiated.")

    # 1. Initialize Queues
    _queue_manager = QueueManager(max_size=1000)
    _system_logger.trace("QueueManager bridge established.")

    # Hardware-Aware Auto-Scaling ---
    target_workers = settings.worker_count
    system_cores = multiprocessing.cpu_count()

    if target_workers <= 0:
        # Reserve 2 cores (one for the OS, one for the async Orchestrator/Ingestor)
        # Cap at 4 by default to prevent a 1.6GB model from eating 20GB+ of RAM on massive servers
        calculated_cores = max(1, system_cores - 2)
        target_workers = min(4, calculated_cores)

    _system_logger.info(f"Hardware Detected: {system_cores} CPU Cores. Spawning {target_workers} Inference Workers...")

    # 2. Spawn the fleet of Inference Workers
    _system_logger.info("Spawning the fleet...")
    for i in range(target_workers):
        worker = InferenceWorker(
            queue_manager=_queue_manager, 
            log_queue=_log_manager.log_queue,
            worker_id=i,
            shutdown_event=_shutdown_event
        )
        worker.start()
        _inference_workers.append(worker)

    # 3. Boot the Senses
    hn_source = LiveHackerNewsSource(_queue_manager)
    
    _system_logger.info("Starting Asynchronous Ingestors...")
    
    try:
        await hn_source.listen()
    except asyncio.CancelledError:
        _system_logger.trace("Main event loop caught CancelledError. Shutting down.")


def main():
    """Entry point for IsoCore."""
    print("--- Starting IsoCore ---")
    print("Press Ctrl+C to stop.")

    # Force "spawn" to prevent async/fork deadlocks on Linux
    multiprocessing.set_start_method("spawn", force=True)
    
    # Boot the logging bridge outside the async loop
    global _log_manager, _system_logger
    try:
        _log_manager = LogManager()
        _log_manager.start()
        _system_logger = LogManager.get_logger("isocore.system")
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