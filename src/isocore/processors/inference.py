"""
IsoCore Inference Worker (src/isocore/processors/inference.py)
"""
import os

# CRITICAL FIX 1: Prevent PyTorch from spawning background threads that thrash the CPU
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"

import multiprocessing
import time
import signal
from typing import List
import torch

from transformers import pipeline

from isocore.core.queue_manager import QueueManager
from isocore.core.log_manager import LogManager
from isocore.models.packet import DataPacket, ResultPacket
from isocore.core.config import settings
from isocore.core.database import DatabaseManager

class InferenceWorker(multiprocessing.Process):
    def __init__(self, queue_manager: QueueManager, log_queue: multiprocessing.Queue, worker_id: int = 0, shutdown_event=None):
        super().__init__(name=f"Worker-CPU-{worker_id}")
        self.queue_manager = queue_manager
        self.log_queue = log_queue
        self.worker_id = worker_id
        self.shutdown_event = shutdown_event
        
        self.logger = None
        self._classifier = None
        self.db = None
        
        self.candidate_labels = [
            "AI Security & Prompt Injection",
            "Red Teaming & Penetration Testing",
            "Malware Analysis & Zero-Days",
            "Infrastructure & DevOps",
            "Startup Funding & Acquisitions",
            "General Tech News"
        ]

    def _load_model(self):
        self.logger.info("Allocating RAM and loading BART-Large weights (~1.6GB)...")
        self._classifier = pipeline(
            task="zero-shot-classification",
            model="facebook/bart-large-mnli",
            device=-1 
        )
        self.logger.info("Zero-Shot Model loaded successfully. Ready for inference.")

    def run(self):
        """The entry point for the isolated OS Process."""
        LogManager.setup_worker(self.log_queue)
        self.logger = LogManager.get_logger("isocore.brain")
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        
        # Enforce the thread limit at the runtime level as well
        torch.set_num_threads(1)

        # Stagger the boot sequence by a few seconds per worker
        # This prevents the workers from colliding when accessing the Hugging Face disk cache
        delay_seconds = self.worker_id * 2.5
        if delay_seconds > 0:
            self.logger.trace(f"Delaying boot by {delay_seconds}s to prevent I/O stampede...")
            time.sleep(delay_seconds)
            
        self.logger.trace("Worker process booted. Environment isolated.")

        self.db = DatabaseManager()
        self._load_model()

        try:
            # Check the switch before pulling new data!
            while not self.shutdown_event.is_set():
                batch = self.queue_manager.get_batch(
                    target_size=settings.batch_size, 
                    max_wait=settings.max_wait_seconds
                )
                if not batch:
                    continue

                self._process_batch(batch)

            # If we break out of the loop because the switch was flipped:
            if self.shutdown_event.is_set():
                self.logger.info("Emergency Stop Event detected. Abandoning backlog and shutting down.")

        except Exception as e:
            self.logger.error(f"Fatal error in InferenceWorker: {e}", exc_info=True)
        finally:
            self.logger.trace("Clearing model from memory...")
            self._classifier = None
            self.logger.info("InferenceWorker has exited cleanly.")

    def _process_batch(self, batch: List[DataPacket]):
        start_time = time.time()
        
        texts = [packet.raw_content for packet in batch]
        ai_predictions = self._classifier(texts, candidate_labels=self.candidate_labels)
        
        if not isinstance(ai_predictions, list):
            ai_predictions = [ai_predictions]
        
        results = []
        for packet, prediction in zip(batch, ai_predictions):
            top_label = prediction['labels'][0]
            confidence = prediction['scores'][0]

            result = ResultPacket(
                original_packet_id=packet.id,
                source=packet.source,
                top_category=top_label,
                confidence_score=round(confidence, 4),
                end_to_end_latency_ms=round((time.time() - packet.timestamp) * 1000, 2)
            )
            results.append(result)
            self.logger.trace(f"[{packet.id[:8]}] AI Output: {top_label.upper()} ({confidence*100:.1f}%)")

        end_time = time.time()
        self.db.save_results(results)

        ai_math_ms = round((end_time - start_time) * 1000, 2)
        avg_wait_ms = round(sum((start_time - p.timestamp) * 1000 for p in batch) / len(batch), 2)
        avg_total_ms = round(sum(r.end_to_end_latency_ms for r in results) / len(results), 2)

        self.logger.debug(
            f"Processed batch of {len(batch)}. "
            f"Queue Wait: {avg_wait_ms}ms | AI Math: {ai_math_ms}ms | Total Latency: {avg_total_ms}ms"
        )