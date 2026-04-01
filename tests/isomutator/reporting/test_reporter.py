"""
ALGORITHM SUMMARY:
This test suite validates the `VulnerabilityReporter` class.
It uses `pytest` fixtures to generate temporary `.jsonl` files containing mock 
strike telemetry. The tests verify that the Reporter correctly leverages `pandas` 
to calculate aggregate metrics (average turn counts, strategy success frequencies) 
and safely renders a `jinja2` HTML report. 

Coverage includes:
1. Happy Path: Standard data aggregation and HTML generation.
2. Edge Cases: Handling completely empty log files without division-by-zero errors.
3. Error Handling: Graceful degradation when the target log file is missing or corrupted.
"""

import json
import logging
import os
import pytest
import pandas as pd
from pathlib import Path

# We will import the Reporter class once it is implemented
from isomutator.reporting.reporter import VulnerabilityReporter

# Setup basic logging for tests
TRACE_LEVEL_NUM = 5
if not hasattr(logging, "TRACE"):
    logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")
    logging.TRACE = TRACE_LEVEL_NUM

logging.basicConfig(level=logging.TRACE)
logger = logging.getLogger(__name__)


@pytest.fixture
def mock_vulnerabilities_file(tmp_path):
    """Generates a temporary JSONL file with simulated exploit data."""
    file_path = tmp_path / "mock_vulnerabilities.jsonl"
    data = [
        {"timestamp": "2026-04-01T10:00:00", "packet_id": "A1", "turn_count": 3, "strategy": "jailbreak", "attack_prompt": "Hack", "model_response": "Failed", "full_history": []},
        {"timestamp": "2026-04-01T10:01:00", "packet_id": "B2", "turn_count": 5, "strategy": "jailbreak", "attack_prompt": "Hack2", "model_response": "Failed2", "full_history": []},
        {"timestamp": "2026-04-01T10:02:00", "packet_id": "C3", "turn_count": 2, "strategy": "model_inversion", "attack_prompt": "Extract", "model_response": "Leaked", "full_history": []}
    ]
    with open(file_path, "w") as f:
        for record in data:
            f.write(json.dumps(record) + "\n")
    return file_path


@pytest.fixture
def empty_vulnerabilities_file(tmp_path):
    """Generates a perfectly empty JSONL file."""
    file_path = tmp_path / "empty_vulnerabilities.jsonl"
    file_path.touch()
    return file_path


@pytest.fixture
def corrupted_vulnerabilities_file(tmp_path):
    """Generates a file with malformed JSON strings."""
    file_path = tmp_path / "corrupt_vulnerabilities.jsonl"
    with open(file_path, "w") as f:
        f.write('{"timestamp": "2026-04-01", "packet_id": "X9", \n') # Broken JSON
        f.write('Not even json\n')
    return file_path


# --- Happy Path ---
def test_reporter_happy_path(mock_vulnerabilities_file):
    logger.log(logging.TRACE, "Testing VulnerabilityReporter happy path.")
    reporter = VulnerabilityReporter(log_path=str(mock_vulnerabilities_file))
    
    # 1. Test DataFrame loading
    df = reporter.load_data()
    assert not df.empty
    assert len(df) == 3
    
    # 2. Test Metric Aggregation
    metrics = reporter.calculate_metrics(df)
    assert metrics["total_exploits"] == 3
    # Jailbreak (3 + 5) / 2 = 4.0 average turns
    assert metrics["strategy_stats"]["jailbreak"]["avg_turns"] == 4.0
    assert metrics["strategy_stats"]["model_inversion"]["count"] == 1
    
    # 3. Test HTML Generation
    html_report = reporter.generate_html_report()
    assert "<html" in html_report.lower()
    assert "jailbreak" in html_report
    assert "model_inversion" in html_report


# --- Edge Cases ---
def test_reporter_empty_file_edge_case(empty_vulnerabilities_file):
    logger.log(logging.TRACE, "Testing VulnerabilityReporter with empty log file.")
    reporter = VulnerabilityReporter(log_path=str(empty_vulnerabilities_file))
    
    df = reporter.load_data()
    assert df.empty
    
    metrics = reporter.calculate_metrics(df)
    assert metrics["total_exploits"] == 0
    assert not metrics["strategy_stats"] # Should be an empty dictionary
    
    html_report = reporter.generate_html_report()
    assert "No vulnerabilities detected" in html_report


# --- Error Handling ---
def test_reporter_missing_file_error():
    logger.log(logging.TRACE, "Testing VulnerabilityReporter with missing file.")
    reporter = VulnerabilityReporter(log_path="does_not_exist.jsonl")
    
    # Should catch FileNotFoundError and return empty dataframe gracefully
    df = reporter.load_data()
    assert df.empty
    
    html_report = reporter.generate_html_report()
    assert "Error" in html_report or "No vulnerabilities detected" in html_report


def test_reporter_corrupted_json_error(corrupted_vulnerabilities_file):
    logger.log(logging.TRACE, "Testing VulnerabilityReporter with corrupted JSON lines.")
    reporter = VulnerabilityReporter(log_path=str(corrupted_vulnerabilities_file))
    
    # Should catch JSONDecodeError, log the issue, and return empty or partial dataframe
    df = reporter.load_data()
    assert df.empty