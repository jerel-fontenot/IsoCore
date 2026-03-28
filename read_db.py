"""
IsoCore Analytics (read_db.py)
------------------------------
Run with: uv run python read_db.py
"""
import sqlite3
import pandas as pd

# Connect to the IsoCore database
with sqlite3.connect("data/isocore.db") as conn:
    
    # 1. Show the overall distribution
    print("\n=== AI CATEGORIZATION DISTRIBUTION ===")
    df_counts = pd.read_sql_query("""
        SELECT top_category, COUNT(*) as count 
        FROM inferences 
        GROUP BY top_category
        ORDER BY count DESC
    """, conn)
    print(df_counts.to_string(index=False))
    
    # 2. Show the raw data (Latest 5 items)
    print("\n=== LATEST INGESTED PACKETS ===")
    df_latest = pd.read_sql_query("""
        SELECT source, top_category, round(confidence*100, 1) as confidence_pct 
        FROM inferences 
        ORDER BY created_at DESC 
        LIMIT 5
    """, conn)
    print(df_latest.to_string(index=False))