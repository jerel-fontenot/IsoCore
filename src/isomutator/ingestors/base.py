"""
isomutator Base Ingestor (src/isomutator/ingestors/base.py)
-----------------------------------------------------
The abstract blueprint for all asynchronous data sources.
"""

import abc
import asyncio
from isomutator.core.queue_manager import QueueManager
from isomutator.core.log_manager import LogManager

class BaseSource(abc.ABC):
    def __init__(self, queue_manager: QueueManager, name: str):
        self.queue_manager = queue_manager
        self.name = name
        # We grab a logger specific to this source (e.g., 'isomutator.ingest.reddit')
        self.logger = LogManager.get_logger(f"isomutator.ingest.{name.lower()}")

    @abc.abstractmethod
    async def listen(self):
        """
        The main infinite loop for this ingestor. 
        Must be implemented by any child class.
        """
        pass
        
    async def _safe_put(self, packet) -> bool:
        """
        A helper method to standardize how subclasses push data.
        """
        self.logger.trace(packet.to_log_trace())
        return await self.queue_manager.async_put(packet)