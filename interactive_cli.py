#!/usr/bin/env python3
import sys
from typing import Dict, Any, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML
import json
from datetime import datetime

# Import our existing clients and utilities
from api_clients.abuseipdb_client import AbuseIPDBClient
from api_clients.virustotal_client import VirusTotalClient
from api_clients.shodan_client import ShodanClient
from core.env_loader import load_env
from cli_app import format_abuseipdb, format_virustotal, format_shodan

class ThreatIntelCLI:
    def __init__(self):
        """Initialize the CLI with rich formatting and API clients."""
        self.console = Console()
        self.style = Style.from_dict({
            'prompt': 'ansicyan bold',
        })
        self.session = PromptSession()
        self.command_completer = WordCompleter([
            'check', 'search', 'help', 'clear', 'exit'
        ])
        
        # Load environment variables
        env_vars = load_env()
        
        # Initialize API clients with their respective API keys
        self.abuseipdb_client = AbuseIPDBClient(api_key=env_vars.get('ABUSEIPDB_API_KEY'))
        self.virustotal_client = VirusTotalClient(api_key=env_vars.get('VIRUSTOTAL_API_KEY'))
        self.shodan_client = ShodanClient(api_key=env_vars.get('SHODAN_API_KEY'))
        
        # Set up command completers
        self.api_completer = WordCompleter(['abuseipdb', 'virustotal', 'shodan'])
        
    def display_welcome(self):
        """Display a welcome message with ASCII art."""
        welcome_text = """
        [bold cyan]Threat Intelligence Aggregator[/bold cyan]
        [dim]Aggregating threat intelligence from multiple sources[/dim]
        
        Available APIs:
        • [green]AbuseIPDB[/green] - IP reputation and abuse reports
        • [blue]VirusTotal[/blue] - Malware and threat detection
        • [yellow]Shodan[/yellow] - Internet device search engine
        
        Type [bold]help[/bold] for available commands
        Type [bold]exit[/bold] to quit
        """
        self.console.print(Panel(welcome_text, title="Welcome", border_style="cyan"))
        
    def display_help(self):
        """Display help information."""
        help_text = """
        [bold]Available Commands:[/bold]
        
        [green]check[/green] <api> <ip/domain>
            Check an IP address or domain using the specified API
            Example: check virustotal 8.8.8.8
            
        [green]search[/green] <api> <query>
            Search for information using the specified API
            Example: search shodan google.com
            
        [green]help[/green]
            Display this help message
            
        [green]clear[/green]
            Clear the screen
            
        [green]exit[/green]
            Exit the application
            
        [bold]Available APIs:[/bold]
        • abuseipdb - IP reputation database
        • virustotal - Malware and threat detection
        • shodan - Internet device search engine
        """
        self.console.print(Panel(help_text, title="Help", border_style="green"))
        
    def check_target(self, api: str, target: str):
        """Check a target using the specified API."""
        if api not in self.clients:
            self.console.print(f"[red]Error: Unknown API '{api}'[/red]")
            return
            
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task(f"Checking {target} with {api}...", total=None)
            
            try:
                if api == 'abuseipdb':
                    result = self.clients[api].check_ip(target)
                    formatted = format_abuseipdb(result)
                elif api == 'virustotal':
                    result = self.clients[api].check_ip(target)
                    formatted = format_virustotal(result)
                elif api == 'shodan':
                    result = self.clients[api].check_ip(target)
                    formatted = format_shodan(result)
                    
                progress.update(task, completed=True)
                
                # Save the result to a file
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"reports/{api}_{target}_{timestamp}.txt"
                with open(filename, 'w') as f:
                    f.write(formatted)
                    
                # Display the result
                self.console.print("\n[bold]Results:[/bold]")
                self.console.print(Panel(formatted, border_style="green"))
                self.console.print(f"\n[dim]Report saved to: {filename}[/dim]")
                
            except Exception as e:
                progress.update(task, completed=True)
                self.console.print(f"[red]Error: {str(e)}[/red]")
                
    def search_target(self, api: str, query: str):
        """Search for information using the specified API."""
        if api not in self.clients:
            self.console.print(f"[red]Error: Unknown API '{api}'[/red]")
            return
            
        if api != 'shodan':
            self.console.print(f"[yellow]Note: Search is only available for Shodan API[/yellow]")
            return
            
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task(f"Searching {query} with {api}...", total=None)
            
            try:
                result = self.clients[api].search_domain(query)
                progress.update(task, completed=True)
                
                if "error" in result:
                    self.console.print(f"[red]Error: {result['error']}[/red]")
                    return
                    
                # Create a table for the results
                table = Table(title=f"Shodan Search Results for {query}")
                table.add_column("IP", style="cyan")
                table.add_column("Port", style="green")
                table.add_column("Product", style="yellow")
                table.add_column("Organization", style="blue")
                
                for item in result.get('data', {}).get('results', [])[:10]:  # Show top 10 results
                    table.add_row(
                        item.get('ip', 'N/A'),
                        str(item.get('port', 'N/A')),
                        item.get('product', 'N/A'),
                        item.get('org', 'N/A')
                    )
                    
                # Save the results
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"reports/shodan_search_{query}_{timestamp}.json"
                with open(filename, 'w') as f:
                    json.dump(result, f, indent=2)
                    
                # Display the results
                self.console.print("\n[bold]Results:[/bold]")
                self.console.print(table)
                self.console.print(f"\n[dim]Full report saved to: {filename}[/dim]")
                
            except Exception as e:
                progress.update(task, completed=True)
                self.console.print(f"[red]Error: {str(e)}[/red]")
                
    def run(self):
        """Run the interactive CLI."""
        self.display_welcome()
        
        while True:
            try:
                # Get user input with command completion
                command = self.session.prompt(
                    HTML('<ansicyan><b>threat-intel></b></ansicyan> '),
                    completer=self.command_completer,
                    style=self.style
                ).strip()
                
                if not command:
                    continue
                    
                # Parse the command
                parts = command.split()
                cmd = parts[0].lower()
                
                if cmd == 'exit':
                    if Confirm.ask("Are you sure you want to exit?"):
                        self.console.print("[yellow]Goodbye![/yellow]")
                        break
                elif cmd == 'help':
                    self.display_help()
                elif cmd == 'clear':
                    self.console.clear()
                    self.display_welcome()
                elif cmd == 'check':
                    if len(parts) != 3:
                        self.console.print("[red]Error: Usage: check <api> <ip/domain>[/red]")
                        continue
                    self.check_target(parts[1].lower(), parts[2])
                elif cmd == 'search':
                    if len(parts) != 3:
                        self.console.print("[red]Error: Usage: search <api> <query>[/red]")
                        continue
                    self.search_target(parts[1].lower(), parts[2])
                else:
                    self.console.print(f"[red]Error: Unknown command '{cmd}'[/red]")
                    self.console.print("Type 'help' for available commands")
                    
            except KeyboardInterrupt:
                continue
            except EOFError:
                break
            except Exception as e:
                self.console.print(f"[red]Error: {str(e)}[/red]")

def main():
    """Main entry point for the interactive CLI."""
    import os
    
    # Create reports directory if it doesn't exist
    os.makedirs("reports", exist_ok=True)
    
    # Run the CLI
    cli = ThreatIntelCLI()
    cli.run()

if __name__ == "__main__":
    main() 