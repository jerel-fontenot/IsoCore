"""
ALGORITHM SUMMARY:
The VulnerabilityReporter acts as the data analytics engine for the IsoMutator framework.
1. It safely ingests the append-only `vulnerabilities.jsonl` log file, line-by-line, 
   to handle potential data corruption gracefully without crashing.
2. It converts the valid JSON payloads into a structured `pandas.DataFrame`.
3. It performs aggregation calculations (grouping by attack strategy, calculating 
   hit counts, and averaging the turn counts required to break the Target AI).
4. It dynamically renders these metrics into a styled HTML report using `jinja2`, 
   providing a standalone, human-readable forensic document.

TECHNOLOGY QUIRKS:
- Manual JSONL Parsing: Instead of using `pd.read_json(lines=True)`, we manually parse 
  the file line-by-line. This ensures that a single corrupted JSON string (e.g., from an 
  unexpected OS shutdown during an active write) does not invalidate the entire dataset.
- Jinja2 Templating: The HTML template is embedded as a raw string to maintain a 
  single-file distribution, avoiding the need for a separate `/templates` directory tree.
"""

import json
import logging
import os
import pandas as pd
import jinja2

# Establish TRACE level logging if it does not exist in the environment
TRACE_LEVEL_NUM = 5
if not hasattr(logging, "TRACE"):
    logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")
    logging.TRACE = TRACE_LEVEL_NUM

def trace(self, message, *args, **kws):
    """Allows logger.trace('message') calls across the codebase."""
    if self.isEnabledFor(TRACE_LEVEL_NUM):
        self._log(TRACE_LEVEL_NUM, message, args, **kws)

logging.Logger.trace = trace


class VulnerabilityReporter:
    """
    Parses Red Team telemetry logs and generates actionable forensic reports.
    Utilizes Pandas for data manipulation and Jinja2 for HTML rendering.
    """
    
    def __init__(self, log_path: str = "vulnerabilities.jsonl"):
        self.logger = logging.getLogger("isomutator.reporting")
        self.log_path = log_path
        self.logger.trace(f"VulnerabilityReporter initialized pointing to {self.log_path}")

    def load_data(self) -> pd.DataFrame:
        """
        Safely loads the JSON Lines file into a Pandas DataFrame.
        Catches FileNotFoundError and JSONDecodeError to degrade gracefully.
        """
        self.logger.trace(f"Attempting to load telemetry data from {self.log_path}")
        
        if not os.path.exists(self.log_path):
            self.logger.error(f"Log file not found: {self.log_path}")
            return pd.DataFrame()

        data = []
        with open(self.log_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError as e:
                    self.logger.warning(f"Skipping corrupted JSON line: {e}")

        df = pd.DataFrame(data)
        self.logger.trace(f"Successfully loaded {len(df)} telemetry records into DataFrame.")
        return df

    def calculate_metrics(self, df: pd.DataFrame) -> dict:
        """
        Aggregates the raw strike data into actionable strategy statistics.
        """
        self.logger.trace("Calculating analytical metrics from DataFrame.")
        
        if df.empty:
            self.logger.debug("DataFrame is empty. Returning zeroed metrics.")
            return {"total_exploits": 0, "strategy_stats": {}}
            
        metrics = {
            "total_exploits": len(df),
            "strategy_stats": {}
        }
        
        # Group by the specific attack vector (e.g., jailbreak, cross_lingual)
        grouped = df.groupby("strategy")
        
        for strategy, group in grouped:
            metrics["strategy_stats"][strategy] = {
                "count": int(len(group)),
                "avg_turns": float(group["turn_count"].mean())
            }
            
        self.logger.trace(f"Calculated metrics for {len(metrics['strategy_stats'])} unique strategies.")
        return metrics

    def generate_html_report(self) -> str:
        """
        Orchestrates the data pipeline and renders the final HTML string.
        """
        self.logger.trace("Initiating HTML report generation pipeline.")
        
        df = self.load_data()
        metrics = self.calculate_metrics(df)
        
        if metrics["total_exploits"] == 0:
            self.logger.debug("No exploits found. Generating empty state HTML.")
            return "<html><body><h1>IsoMutator Red Team Report</h1><p>No vulnerabilities detected.</p></body></html>"

        # Embedded Jinja2 Template
        template_str = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>IsoMutator Forensic Report</title>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f9; color: #333; margin: 40px; }
                h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
                h2 { color: #2980b9; margin-top: 30px; }
                .metric-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }
                .total-exploits { font-size: 2em; font-weight: bold; color: #e74c3c; }
                table { width: 100%; border-collapse: collapse; margin-top: 15px; background: white; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #34495e; color: white; }
                tr:hover { background-color: #f1f1f1; }
            </style>
        </head>
        <body>
            <h1>IsoMutator AI Vulnerability Report</h1>
            
            <div class="metric-card">
                <h2>Executive Summary</h2>
                <p>Total Confirmed Exploits: <span class="total-exploits">{{ metrics.total_exploits }}</span></p>
            </div>

            <h2>Attack Vector Analysis</h2>
            <table>
                <thead>
                    <tr>
                        <th>Strategy</th>
                        <th>Successful Breaches</th>
                        <th>Average Turns to Exploit</th>
                    </tr>
                </thead>
                <tbody>
                    {% for strategy, stats in metrics.strategy_stats.items() %}
                    <tr>
                        <td><strong>{{ strategy }}</strong></td>
                        <td>{{ stats.count }}</td>
                        <td>{{ "%.1f"|format(stats.avg_turns) }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            
            <p style="margin-top: 40px; font-size: 0.9em; color: #7f8c8d;">
                Report automatically generated by the IsoMutator Stateful AI Red Teaming Framework.
            </p>
        </body>
        </html>
        """
        
        self.logger.trace("Rendering Jinja2 template with dynamic metrics.")
        template = jinja2.Template(template_str)
        html_output = template.render(metrics=metrics)
        
        self.logger.info("HTML Forensic Report successfully generated.")
        return html_output

    def save_report(self, output_path: str = "report.html"):
        """Utility method to dump the rendered HTML to disk."""
        html_content = self.generate_html_report()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        self.logger.info(f"Report saved to disk at {output_path}")