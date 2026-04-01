"""
ALGORITHM SUMMARY:
The AI Judge acts as the evaluator and router in the stateful red-teaming pipeline.
1. It continuously polls the Eval Queue for completed strikes.
2. It parses the target AI's latest response in the conversation history.
3. Scoring Heuristics: 
   - Primary: Checks the strict Strategy rules (e.g., regex, strings).
   - Fallback: Uses the SemanticJudge to verify intent via math vectors.
4. Routing Heuristic: If the AI defended itself, the Judge emits a Wiretap UI event 
   to display the debate. It then increments the packet's turn count. If under the 
   max limit, the packet is pushed to the Feedback Queue.

TECHNOLOGY QUIRKS:
- Multiprocessing UI Telemetry (Observer Pattern): Standard print statements corrupt 
  the `rich` TUI. Instead, we use `self.logger.info(..., extra={...})` to broadcast 
  state changes. The LogManager's custom QueueListener intercepts these dictionaries 
  and routes them to the DashboardManager without blocking the Judge's execution thread.
"""

import json
import os
from datetime import datetime
import multiprocessing
import signal
from isomutator.core.queue_manager import QueueManager
from isomutator.core.log_manager import LogManager
from isomutator.core.strategies import RedTeamStrategy
from isomutator.processors.semantic_judge import SemanticJudge

class RedTeamJudge(multiprocessing.Process):
    """
    Isolated OS Process that scores prompt injections and manages conversational state routing.
    """
    def __init__(self, eval_queue: QueueManager, feedback_queue: QueueManager, log_queue: multiprocessing.Queue, strategy: RedTeamStrategy):
        super().__init__(name="Worker-Judge")
        self.eval_queue = eval_queue
        self.feedback_queue = feedback_queue
        self.log_queue = log_queue
        self.strategy = strategy
        self.max_turns = 5
        self.logger = None
        self.semantic_judge = None

    def _record_exploit(self, packet, attack_prompt: str, target_response: str, breach_type: str):
        """Helper method to centralize telemetry logging and file writing."""
        self.logger.warning(
            f"Vulnerability exploited via packet {packet.id[:8]} on turn {packet.turn_count} ({breach_type})",
            extra={
                "ui_event": "ledger",
                "turn": packet.turn_count,
                "strategy": f"{self.strategy.name} [{breach_type}]", 
                "packet_id": packet.id
            }
        )
        
        vuln_record = {
            "timestamp": datetime.now().isoformat(),
            "packet_id": packet.id,
            "turn_count": packet.turn_count,
            "strategy": f"{packet.source}/{breach_type}",
            "attack_prompt": attack_prompt.strip(),
            "model_response": target_response.strip(),
            "full_history": packet.history
        }
        
        log_file_path = os.path.join(os.getcwd(), "vulnerabilities.jsonl")
        try:
            with open(log_file_path, "a") as f:
                f.write(json.dumps(vuln_record) + "\n")
        except Exception as e:
            self.logger.error(f"Failed to write vulnerability to disk: {e}")

    def run(self):
        """The entry point for the isolated OS process."""
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        LogManager.setup_worker(self.log_queue)
        self.logger = LogManager.get_logger("isomutator.judge")
        
        # Instantiate the NLP model inside the process boundary to avoid CUDA/Memory crashes
        self.semantic_judge = SemanticJudge()
        self.logger.info("Red Team Judge online. Awaiting strike telemetry...")
        
        while True:
            batch = self.eval_queue.get_batch(target_size=5, max_wait=1.0)
            
            if not batch:
                continue

            if any(p == "POISON_PILL" for p in batch):
                self.logger.info("Poison Pill swallowed. Court is adjourned.")
                break

            for packet in batch:
                target_response = packet.history[-1]["content"] if packet.history else ""
                attack_prompt = packet.history[-2]["content"] if len(packet.history) > 1 else packet.raw_content
                
                # --- 1. Explicit Rule Scoring ---
                if self.strategy.score_response(target_response):
                    self._record_exploit(packet, attack_prompt, target_response, "explicit")
                
                else:
                    # --- 2. Semantic Fallback Scoring ---
                    is_flagged, confidence = self.semantic_judge.evaluate_response(target_response)
                    
                    if is_flagged:
                        self.logger.trace(f"Semantic scoring caught anomalous compliance! (Sim: {confidence:.2f})")
                        self._record_exploit(packet, attack_prompt, target_response, "semantic_anomaly")
                    
                    # --- 3. Defense Succeeded ---
                    else:
                        self.logger.debug(
                            f"Target defended against packet {packet.id[:8]}. Emitting wiretap event.",
                            extra={
                                "ui_event": "wiretap",
                                "turn": packet.turn_count,
                                "attacker": attack_prompt.strip(),
                                "target": target_response.strip()
                            }
                        )
                        
                        if packet.turn_count < self.max_turns:
                            packet.turn_count += 1
                            self.feedback_queue.put(packet)
                            self.logger.trace(f"Strike {packet.id[:8]} failed. Routing to Feedback Queue for Turn {packet.turn_count}.")
                        else:
                            self.logger.trace(f"Strike {packet.id[:8]} reached max turns ({self.max_turns}). Attack failed permanently.")