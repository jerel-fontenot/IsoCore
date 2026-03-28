-- IsoCore Initial Schema (src/isocore/core/schema.sql)

-- In database design, SQL is divided into two main categories:

-- DDL (Data Definition Language): These are CREATE, ALTER, and DROP statements. They define the architecture of your database. These are static, run very rarely (usually only on boot or during an upgrade), and belong in external .sql files so you can easily track version history.

-- DML (Data Manipulation Language): These are SELECT, INSERT, UPDATE, and DELETE. These are the actions your application takes every second. Because they are the core behavior of your Python app, they stay in the Python files.

CREATE TABLE IF NOT EXISTS inferences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_id TEXT NOT NULL,
    source TEXT NOT NULL,
    top_category TEXT NOT NULL,
    confidence REAL NOT NULL,
    latency_ms REAL NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);