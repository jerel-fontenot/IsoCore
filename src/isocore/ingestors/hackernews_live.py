"""
IsoCore Hacker News Ingestor (src/isocore/ingestors/hackernews_live.py)
-----------------------------------------------------------------------
Streams live tech and cybersecurity discussions directly into the data queue.
"""

import asyncio
import aiohttp
from isocore.ingestors.base import BaseSource
from isocore.models.packet import DataPacket

class LiveHackerNewsSource(BaseSource):
    def __init__(self, queue_manager):
        super().__init__(queue_manager, name="HackerNewsLive")
        self.base_url = "https://hacker-news.firebaseio.com/v0"
        self.seen_items = set()

    async def listen(self):
        self.logger.info("Connecting to Hacker News live stream...")
        
        # We use aiohttp to make non-blocking asynchronous web requests
        async with aiohttp.ClientSession() as session:
            try:
                while True:
                    # 1. Ask HN for the IDs of the newest stories
                    async with session.get(f"{self.base_url}/newstories.json") as resp:
                        latest_ids = await resp.json()
                        
                    if not latest_ids:
                        await asyncio.sleep(5.0)
                        continue
                        
                    # 2. Process only the 100 most recent IDs to catch new data
                    for item_id in latest_ids[:100]:
                        if item_id in self.seen_items:
                            continue
                            
                        self.seen_items.add(item_id)
                        
                        # 3. Fetch the actual content of the new story
                        async with session.get(f"{self.base_url}/item/{item_id}.json") as item_resp:
                            item = await item_resp.json()
                            
                            if not item or 'title' not in item:
                                continue
                            
                            # Combine title and text (if it exists)
                            raw_text = item.get('title', '')
                            if 'text' in item:
                                raw_text += " | " + item['text']
                                
                            # 4. Package it for the IsoCore queue
                            packet = DataPacket(
                                raw_content=raw_text,
                                source=f"hackernews/item/{item_id}",
                                metadata={"author": item.get('by', 'anon')}
                            )
                            
                            success = await self._safe_put(packet)
                            if not success:
                                self.logger.debug("Queue full. Backing off.")
                                await asyncio.sleep(2.0)
                                
                    # 5. Wait 10 seconds before polling again to be polite to their servers
                    await asyncio.sleep(10.0)
                    
            except asyncio.CancelledError:
                self.logger.info("Hacker News listener cancelled. Closing network connection cleanly.")
                raise
            except Exception as e:
                self.logger.error(f"Fatal Hacker News stream error: {e}", exc_info=True)