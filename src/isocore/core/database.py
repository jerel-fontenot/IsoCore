"""
IsoCore Database Sink (src/isocore/core/database.py)
----------------------------------------------------
Handles batch inserts of AI classifications into a local SQLite file.
"""

import sqlite3
from pathlib import Path
from typing import List

from isocore.models.packet import ResultPacket
from isocore.core.log_manager import LogManager
from isocore.core.config import settings

class DatabaseManager:
    def __init__(self):
        # Grab the path from our central config and ensure the directory exists
        self.db_path = Path(settings.db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.logger = LogManager.get_logger("isocore.db")
        self._init_db()

    def _init_db(self):
        """Creates the tables using the external SQL schema file."""
        # Dynamically locate schema.sql relative to this python file
        schema_path = Path(__file__).parent / "schema.sql"
        
        with open(schema_path, "r") as f:
            schema_sql = f.read()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Use executescript() to run the entire SQL file at once
            cursor.executescript(schema_sql)
            conn.commit()
            
        self.logger.trace("SQLite tables verified against schema.sql.")

    def save_results(self, results: List[ResultPacket]):
        """Executes a highly efficient bulk insert for an entire batch."""
        if not results:
            return

        payload = [
            (r.original_packet_id, r.source, r.top_category, r.confidence_score, r.end_to_end_latency_ms)
            for r in results
        ]

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.executemany("""
                    INSERT INTO inferences (packet_id, source, top_category, confidence, latency_ms)
                    VALUES (?, ?, ?, ?, ?)
                """, payload)
                conn.commit()
            
            self.logger.debug(f"Saved {len(results)} AI classifications to disk.")
        except Exception as e:
            self.logger.error(f"Failed to write to database: {e}", exc_info=True)