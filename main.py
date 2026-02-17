#!/usr/bin/env python3
"""
IPv6 Intelligent Crawler - Main Entry Point
سیستم هوشمند کشف سرورهای وب IPv6

Usage:
    python main.py                    # Run full crawler
    python main.py --mode collect     # Only collect seeds
    python main.py --mode train       # Only train model
    python main.py --mode scan        # Only scan addresses
    python main.py --mode report      # Generate report
"""

import asyncio
import argparse
import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
import yaml

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.panel import Panel
from rich.logging import RichHandler

# Import our modules
from src.seed_collector import SeedCollector
from src.feature_extractor import IPv6FeatureExtractor, AddressPatternAnalyzer
from src.ml_model import EnsembleIPv6Predictor, IPv6ActivePredictor
from src.address_generator import SmartAddressGenerator, IPv6AddressGenerator
from src.prober import IPv6Prober, ProbeResultStore
from src.fingerprinter import InfrastructureFingerprinter
from src.feedback_loop import AdaptiveFeedbackLoop, FeedbackCollector
from src.database import CrawlerDatabase

# Setup rich console
console = Console()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)


class IPv6Crawler:
    """
    Main IPv6 Crawler orchestrator.
    
    Coordinates all components:
    - Seed collection
    - Feature extraction
    - ML training
    - Address generation
    - Probing
    - Fingerprinting
    - Feedback loop
    """
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)
        self.base_dir = Path(__file__).parent
        self.data_dir = self.base_dir / "data"
        self.models_dir = self.data_dir / "models"
        self.results_dir = self.data_dir / "results"
        
        # Ensure directories exist
        self.data_dir.mkdir(exist_ok=True)
        self.models_dir.mkdir(exist_ok=True)
        self.results_dir.mkdir(exist_ok=True)
        
        # Initialize components
        self._init_components()
        
        # Statistics
        self.stats = {
            'start_time': None,
            'seeds_collected': 0,
            'addresses_generated': 0,
            'addresses_probed': 0,
            'active_found': 0,
            'fingerprints_collected': 0
        }
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        config_file = Path(config_path)
        if config_file.exists():
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        else:
            logger.warning(f"Config file not found: {config_path}, using defaults")
            return self._default_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            'scanner': {
                'max_concurrent': 50,
                'timeout': 5,
                'ports': [80, 443],
                'rate_limit': 30
            },
            'ml': {
                'model_type': 'ensemble',
                'n_estimators': 100,
                'test_size': 0.2
            },
            'generator': {
                'batch_size': 1000,
                'min_confidence': 0.6
            },
            'feedback': {
                'enabled': True,
                'retrain_threshold': 500
            }
        }
    
    def _init_components(self):
        """Initialize all crawler components"""
        # Database
        db_path = self.config.get('database', {}).get('path', 'data/ipv6_crawler.db')
        self.db = CrawlerDatabase(db_path)
        
        # Seed collector
        self.seed_collector = SeedCollector(self.config)
        
        # Feature extractor
        self.feature_extractor = IPv6FeatureExtractor()
        
        # ML predictor
        self.predictor = EnsembleIPv6Predictor(self.config.get('ml', {}))
        
        # Address generator
        self.generator = SmartAddressGenerator(
            predictor=self.predictor,
            config=self.config.get('generator', {})
        )
        
        # Prober
        self.prober = IPv6Prober(self.config.get('scanner', {}))
        
        # Fingerprinter
        self.fingerprinter = InfrastructureFingerprinter(self.config.get('fingerprinting', {}))
        
        # Feedback loop
        self.feedback_loop = AdaptiveFeedbackLoop(
            predictor=self.predictor,
            generator=self.generator,
            config=self.config.get('feedback', {})
        )
        
        # Result store
        self.probe_store = ProbeResultStore()
    
    async def collect_seeds(self) -> int:
        """Collect seed addresses from various sources"""
        console.print(Panel("[bold blue]Phase 1: Collecting Seed Addresses[/bold blue]"))
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Collecting seeds...", total=None)
            
            seeds = await self.seed_collector.collect_all(self.data_dir)
            
            progress.update(task, description=f"Collected {len(seeds)} seeds")
        
        # Save seeds
        self.seed_collector.save_seeds(self.data_dir / "seeds" / "collected_seeds.json")
        
        # Add to database
        for seed in seeds:
            self.db.add_seed(
                address=seed.address,
                source=seed.source,
                domain=seed.domain,
                metadata=seed.metadata
            )
        
        self.stats['seeds_collected'] = len(seeds)
        
        console.print(f"[green]✓[/green] Collected {len(seeds)} seed addresses")
        return len(seeds)
    
    async def probe_seeds(self) -> Dict[str, Any]:
        """Probe collected seeds to identify active addresses"""
        console.print(Panel("[bold blue]Phase 2: Probing Seed Addresses[/bold blue]"))
        
        # Get seed addresses
        addresses = self.seed_collector.get_addresses()
        
        if not addresses:
            console.print("[yellow]No seeds to probe[/yellow]")
            return {}
        
        console.print(f"Probing {len(addresses)} addresses...")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console
        ) as progress:
            task = progress.add_task("Probing...", total=len(addresses))
            
            def update_progress(addr, responses):
                progress.update(task, advance=1)
            
            results = await self.prober.probe_batch(
                addresses,
                probe_type='http',
                progress_callback=update_progress
            )
        
        # Store results
        self.probe_store.add_results(results)
        
        # Update database
        for addr, responses in results.items():
            for response in responses:
                self.db.add_probe_result(
                    address=response.address,
                    port=response.port,
                    result=response.result.value,
                    response_time_ms=response.response_time_ms,
                    http_status=response.http_status,
                    server_header=response.server_header
                )
        
        active = self.prober.filter_active(results)
        stats = self.prober.get_statistics()
        
        self.stats['addresses_probed'] = stats['total_probed']
        self.stats['active_found'] = stats['active']
        
        console.print(f"[green]✓[/green] Found {len(active)} active addresses out of {len(addresses)}")
        return stats
    
    async def train_model(self) -> Dict[str, Any]:
        """Train the ML model on labeled data"""
        console.print(Panel("[bold blue]Phase 3: Training ML Model[/bold blue]"))
        
        # Get labeled data from database
        active_addresses = self.db.get_active_addresses()
        inactive_addresses = self.db.get_inactive_addresses()
        
        if len(active_addresses) < 10 or len(inactive_addresses) < 10:
            console.print("[yellow]Not enough labeled data for training[/yellow]")
            console.print(f"  Active: {len(active_addresses)}, Inactive: {len(inactive_addresses)}")
            return {}
        
        console.print(f"Training with {len(active_addresses)} active and {len(inactive_addresses)} inactive addresses")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Training model...", total=None)
            
            stats = self.predictor.train(active_addresses, inactive_addresses)
            
            progress.update(task, description="Training complete")
        
        # Save model
        self.predictor.save(self.models_dir)
        
        # Display metrics
        metrics = stats.get('metrics', {})
        table = Table(title="Model Performance")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        for metric, value in metrics.items():
            if isinstance(value, float):
                table.add_row(metric, f"{value:.4f}")
        
        console.print(table)
        
        return stats
    
    async def generate_and_probe(self, count: int = 1000) -> Dict[str, Any]:
        """Generate new addresses and probe them"""
        console.print(Panel("[bold blue]Phase 4: Generating and Probing Addresses[/bold blue]"))
        
        # Learn from existing active addresses
        active_addresses = self.db.get_active_addresses()
        self.generator.learn_from_seeds(active_addresses)
        
        # Generate candidates
        console.print(f"Generating {count} candidate addresses...")
        candidates = self.generator.generate_candidates(count, filter_by_prediction=True)
        
        if not candidates:
            console.print("[yellow]No candidates generated[/yellow]")
            return {}
        
        console.print(f"Generated {len(candidates)} candidates")
        
        # Store generated addresses
        self.db.add_generated_addresses([
            {
                'address': c.address,
                'generation_method': c.generation_method,
                'confidence': c.confidence,
                'source_prefix': c.source_prefix
            }
            for c in candidates
        ])
        
        # Probe them
        addresses = [c.address for c in candidates]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console
        ) as progress:
            task = progress.add_task("Probing generated addresses...", total=len(addresses))
            
            def update_progress(addr, responses):
                progress.update(task, advance=1)
            
            results = await self.prober.probe_batch(
                addresses,
                probe_type='http',
                progress_callback=update_progress
            )
        
        # Record feedback
        self.feedback_loop.record_feedback(candidates, results)
        
        # Store results
        self.probe_store.add_results(results)
        
        active = self.prober.filter_active(results)
        
        self.stats['addresses_generated'] += len(candidates)
        self.stats['addresses_probed'] += len(results)
        self.stats['active_found'] += len(active)
        
        console.print(f"[green]✓[/green] Found {len(active)} new active addresses")
        
        return {
            'generated': len(candidates),
            'probed': len(results),
            'active': len(active),
            'hit_rate': len(active) / len(results) if results else 0
        }
    
    async def fingerprint_active(self) -> Dict[str, Any]:
        """Fingerprint active addresses"""
        console.print(Panel("[bold blue]Phase 5: Infrastructure Fingerprinting[/bold blue]"))
        
        active_addresses = self.db.get_active_addresses(limit=500)
        
        if not active_addresses:
            console.print("[yellow]No active addresses to fingerprint[/yellow]")
            return {}
        
        console.print(f"Fingerprinting {len(active_addresses)} active addresses...")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console
        ) as progress:
            task = progress.add_task("Fingerprinting...", total=len(active_addresses))
            
            fingerprints = await self.fingerprinter.fingerprint_batch(
                active_addresses,
                max_concurrent=20
            )
            
            progress.update(task, completed=len(active_addresses))
        
        # Store fingerprints
        for addr, fp in fingerprints.items():
            self.db.add_fingerprint(fp.to_dict())
        
        # Get summary
        summary = self.fingerprinter.summarize_fingerprints(fingerprints)
        
        self.stats['fingerprints_collected'] = len(fingerprints)
        
        # Display summary
        table = Table(title="Fingerprinting Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Addresses", str(summary.get('total_addresses', 0)))
        table.add_row("Web Servers", str(summary.get('web_servers', 0)))
        table.add_row("HTTPS Enabled", f"{summary.get('https_ratio', 0)*100:.1f}%")
        table.add_row("Behind CDN", f"{summary.get('cdn_ratio', 0)*100:.1f}%")
        table.add_row("Avg Security Score", f"{summary.get('average_security_score', 0):.2f}")
        
        console.print(table)
        
        return summary
    
    async def run_iteration(self, iteration: int = 1) -> Dict[str, Any]:
        """Run one iteration of the feedback loop"""
        console.print(Panel(f"[bold magenta]Iteration {iteration}[/bold magenta]"))
        
        # Generate and probe
        results = await self.generate_and_probe(
            count=self.config.get('generator', {}).get('batch_size', 1000)
        )
        
        # Check if model needs retraining
        if self.feedback_loop.should_retrain():
            console.print("[yellow]Retraining model with new feedback...[/yellow]")
            self.feedback_loop.retrain_model()
        
        return results
    
    async def run(self, iterations: int = 5):
        """Run the full crawler pipeline"""
        self.stats['start_time'] = datetime.now()
        
        console.print(Panel.fit(
            "[bold green]IPv6 Intelligent Crawler[/bold green]\n"
            "Starting crawler pipeline...",
            title="🌐 IPv6 Crawler"
        ))
        
        try:
            # Phase 1: Collect seeds
            await self.collect_seeds()
            
            # Phase 2: Probe seeds
            await self.probe_seeds()
            
            # Phase 3: Train model
            await self.train_model()
            
            # Phase 4 & 5: Iterative discovery
            for i in range(iterations):
                await self.run_iteration(i + 1)
            
            # Phase 6: Final fingerprinting
            await self.fingerprint_active()
            
            # Generate report
            self.generate_report()
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted by user[/yellow]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            logger.exception("Crawler error")
            raise
    
    def generate_report(self):
        """Generate final report"""
        console.print(Panel("[bold blue]Final Report[/bold blue]"))
        
        # Overall statistics
        db_stats = self.db.get_statistics()
        
        table = Table(title="Crawler Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Seeds Collected", str(self.stats['seeds_collected']))
        table.add_row("Addresses Generated", str(self.stats['addresses_generated']))
        table.add_row("Addresses Probed", str(self.stats['addresses_probed']))
        table.add_row("Active Found", str(self.stats['active_found']))
        table.add_row("Fingerprints Collected", str(self.stats['fingerprints_collected']))
        
        if self.stats['addresses_probed'] > 0:
            hit_rate = self.stats['active_found'] / self.stats['addresses_probed']
            table.add_row("Overall Hit Rate", f"{hit_rate*100:.2f}%")
        
        console.print(table)
        
        # Feedback statistics
        feedback_stats = self.feedback_loop.get_performance_report()
        
        if feedback_stats.get('overall_stats'):
            overall = feedback_stats['overall_stats']
            table2 = Table(title="Model Performance")
            table2.add_column("Metric", style="cyan")
            table2.add_column("Value", style="green")
            
            table2.add_row("Accuracy", f"{overall.get('accuracy', 0)*100:.2f}%")
            table2.add_row("Precision", f"{overall.get('precision', 0)*100:.2f}%")
            table2.add_row("Recall", f"{overall.get('recall', 0)*100:.2f}%")
            table2.add_row("F1 Score", f"{overall.get('f1_score', 0)*100:.2f}%")
            
            console.print(table2)
        
        # Save report
        report_path = self.results_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.db.export_to_json(report_path)
        console.print(f"\n[green]Report saved to: {report_path}[/green]")


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="IPv6 Intelligent Crawler")
    parser.add_argument(
        '--mode',
        choices=['full', 'collect', 'train', 'scan', 'report'],
        default='full',
        help='Crawler mode'
    )
    parser.add_argument(
        '--config',
        default='config.yaml',
        help='Path to config file'
    )
    parser.add_argument(
        '--iterations',
        type=int,
        default=5,
        help='Number of discovery iterations'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        default=1000,
        help='Batch size for address generation'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create crawler
    crawler = IPv6Crawler(config_path=args.config)
    
    if args.mode == 'full':
        await crawler.run(iterations=args.iterations)
    elif args.mode == 'collect':
        await crawler.collect_seeds()
    elif args.mode == 'train':
        await crawler.probe_seeds()
        await crawler.train_model()
    elif args.mode == 'scan':
        await crawler.generate_and_probe(count=args.batch_size)
    elif args.mode == 'report':
        crawler.generate_report()


if __name__ == "__main__":
    asyncio.run(main())
