"""
ALGORITHM SUMMARY:
The DashboardManager is a self-contained UI engine that renders a live, non-blocking 
terminal interface using the `rich` library. It acts as an observer, polling the 
multiprocessing queues and an internal event buffer to continuously redraw the screen 
state. The layout is strictly compositional, combining discrete Panel, Table, and Text 
objects into a master layout grid.

TECHNOLOGY QUIRKS:
- Rich Live Context: The `rich.live.Live` manager hijacks `stdout`. Any standard `print()` 
statements from background workers will violently corrupt the rendering buffer. All 
text must be routed into this class's internal state buffers for safe rendering.
- Deque Buffers: We use `collections.deque` to hold the Wiretap and Ledger histories. 
This automatically drops old messages when the buffer hits its maximum length, 
preventing memory leaks and UI overflow without manual garbage collection.
"""

import asyncio
from collections import deque
from datetime import datetime

from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align

from isomutator.core.queue_manager import QueueManager
from isomutator.core.log_manager import LogManager


class DashboardManager:
    """
    Encapsulates the rendering logic and state for the Terminal User Interface.
    Maintains abstraction by exclusively reading from provided queues and buffers.
    """
    def __init__(self, attack_queue: QueueManager, eval_queue: QueueManager, feedback_queue: QueueManager):
        self.logger = LogManager.get_logger("isomutator.ui")
        
        # Internal State References
        self.attack_queue = attack_queue
        self.eval_queue = eval_queue
        self.feedback_queue = feedback_queue
        
        # State Buffers (Automatically truncate to fit the screen)
        self.wiretap_buffer = deque(maxlen=15)
        self.ledger_buffer = deque(maxlen=5)
        
        self.start_time = datetime.now()
        self.is_running = False

    def add_wiretap_event(self, turn: int, attacker_text: str, target_text: str):
        """Thread-safe injection of debate text into the UI buffer."""
        self.wiretap_buffer.append({
            "turn": turn,
            "attacker": attacker_text,
            "target": target_text
        })
        self.logger.debug("Wiretap buffer state updated.")

    def add_vulnerability(self, turn: int, strategy: str, packet_id: str):
        """Thread-safe injection of a successful breach into the UI buffer."""
        self.ledger_buffer.append({
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "turn": turn,
            "strategy": strategy,
            "id": packet_id[:8]
        })
        self.logger.debug("Vulnerability ledger state updated.")

    def _generate_layout(self) -> Layout:
        """The factory method that constructs the compositional grid."""
        self.logger.trace("Constructing Rich layout grid.")
        layout = Layout()
        
        # Split into Top Header and Main Body
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body")
        )
        
        # Split Body into Left (Wiretap) and Right (Telemetry/Ledger)
        layout["body"].split_row(
            Layout(name="wiretap", ratio=2),
            Layout(name="sidebar", ratio=1)
        )
        
        # Split Right Sidebar into Queues and Vulnerabilities
        layout["sidebar"].split_column(
            Layout(name="telemetry", size=10),
            Layout(name="ledger")
        )
        
        return layout

    def _build_header(self) -> Panel:
        """Constructs the top status bar."""
        uptime = datetime.now() - self.start_time
        uptime_str = str(uptime).split('.')[0] # Strip microseconds
        
        header_text = Table.grid(expand=True)
        header_text.add_column(justify="left", ratio=1)
        header_text.add_column(justify="center", ratio=1)
        header_text.add_column(justify="right", ratio=1)
        
        header_text.add_row(
            "[bold cyan]IsoMutator[/bold cyan] v2.0",
            "[bold green]SYSTEM ONLINE[/bold green]",
            f"Uptime: [yellow]{uptime_str}[/yellow]"
        )
        return Panel(header_text, style="white")

    def _build_wiretap(self) -> Panel:
        """Constructs the scrolling text panel for the multi-turn debate."""
        content = Text()
        for event in reversed(self.wiretap_buffer):
            content.append(f"[TURN {event['turn']}]\n", style="bold magenta")
            content.append("Attacker: ", style="bold red")
            # Truncate to keep the UI clean
            attacker_text = event['attacker'][:150] + "..." if len(event['attacker']) > 150 else event['attacker']
            content.append(f"{attacker_text}\n")
            
            content.append("Target  : ", style="bold blue")
            target_text = event['target'][:150] + "..." if len(event['target']) > 150 else event['target']
            content.append(f"{target_text}\n\n")
            
        if not self.wiretap_buffer:
            content.append("\nAwaiting conversational interception...\n", style="dim italic")

        return Panel(content, title="[bold]Live Wiretap (Intercepted Comms)[/bold]", border_style="cyan")

    def _build_telemetry(self) -> Panel:
        """Constructs the queue size monitors."""
        table = Table(expand=True, show_header=False, box=None)
        table.add_column("Queue", justify="left", style="bold")
        table.add_column("Count", justify="right", style="yellow")
        
        # We use get_approximate_size to prevent deadlocking the OS pipes
        table.add_row("Attack Queue (Outbound)", str(max(0, self.attack_queue.get_approximate_size())))
        table.add_row("Eval Queue (Inbound)", str(max(0, self.eval_queue.get_approximate_size())))
        table.add_row("Feedback Queue (Routing)", str(max(0, self.feedback_queue.get_approximate_size())))
        
        return Panel(Align.center(table, vertical="middle"), title="[bold]Queue Telemetry[/bold]", border_style="yellow")

    def _build_ledger(self) -> Panel:
        """Constructs the critical alerts panel for successful jailbreaks."""
        table = Table(expand=True)
        table.add_column("Time", justify="left", style="dim")
        table.add_column("ID", justify="left", style="cyan")
        table.add_column("Turn", justify="center", style="magenta")
        table.add_column("Strategy", justify="left", style="red")
        
        for vuln in self.ledger_buffer:
            table.add_row(
                vuln["timestamp"],
                vuln["id"],
                str(vuln["turn"]),
                vuln["strategy"].split("/")[-1] # Show just the final strategy name
            )
            
        if not self.ledger_buffer:
            return Panel(Align.center(Text("No vulnerabilities detected yet.", style="dim italic"), vertical="middle"), title="[bold red]Vulnerability Ledger[/bold red]", border_style="red")
            
        return Panel(table, title="[bold red]Vulnerability Ledger[/bold red]", border_style="red")

    async def render_loop(self):
        """
        The main asynchronous UI loop. 
        Reconstructs the layout and yields control back to the event loop rapidly.
        """
        self.logger.info("Dashboard rendering engine initialized.")
        self.is_running = True
        
        layout = self._generate_layout()
        
        try:
            # The Live context manager takes control of the terminal screen
            with Live(layout, refresh_per_second=4, screen=True) as live:
                while self.is_running:
                    # Refreshing UI panels.
                    layout["header"].update(self._build_header())
                    layout["wiretap"].update(self._build_wiretap())
                    layout["telemetry"].update(self._build_telemetry())
                    layout["ledger"].update(self._build_ledger())
                    
                    # Sleep briefly to yield CPU back to the Mutator
                    await asyncio.sleep(0.25)
                    
        except asyncio.CancelledError:
            self.logger.info("Dashboard rendering engine shutting down.")
        finally:
            self.is_running = False