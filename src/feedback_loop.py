"""
Feedback Loop Module
سیستم بازخورد برای بهبود مداوم مدل
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import json
import numpy as np

from .ml_model import EnsembleIPv6Predictor, IPv6ActivePredictor
from .address_generator import SmartAddressGenerator, GeneratedAddress
from .prober import ProbeResponse, ProbeResult

logger = logging.getLogger(__name__)


@dataclass
class FeedbackEntry:
    """Single feedback entry from a probe result"""
    address: str
    predicted_active: bool
    predicted_confidence: float
    actual_active: bool
    generation_method: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    @property
    def is_correct(self) -> bool:
        return self.predicted_active == self.actual_active
    
    @property
    def is_false_positive(self) -> bool:
        return self.predicted_active and not self.actual_active
    
    @property
    def is_false_negative(self) -> bool:
        return not self.predicted_active and self.actual_active
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'address': self.address,
            'predicted_active': self.predicted_active,
            'predicted_confidence': self.predicted_confidence,
            'actual_active': self.actual_active,
            'generation_method': self.generation_method,
            'timestamp': self.timestamp.isoformat(),
            'is_correct': self.is_correct
        }


@dataclass
class FeedbackStats:
    """Statistics from feedback data"""
    total_predictions: int = 0
    correct_predictions: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_positives: int = 0
    true_negatives: int = 0
    
    @property
    def accuracy(self) -> float:
        if self.total_predictions == 0:
            return 0.0
        return self.correct_predictions / self.total_predictions
    
    @property
    def precision(self) -> float:
        tp_fp = self.true_positives + self.false_positives
        if tp_fp == 0:
            return 0.0
        return self.true_positives / tp_fp
    
    @property
    def recall(self) -> float:
        tp_fn = self.true_positives + self.false_negatives
        if tp_fn == 0:
            return 0.0
        return self.true_positives / tp_fn
    
    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        if p + r == 0:
            return 0.0
        return 2 * p * r / (p + r)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_predictions': self.total_predictions,
            'correct_predictions': self.correct_predictions,
            'false_positives': self.false_positives,
            'false_negatives': self.false_negatives,
            'true_positives': self.true_positives,
            'true_negatives': self.true_negatives,
            'accuracy': self.accuracy,
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score
        }


class FeedbackCollector:
    """Collect and store feedback from probe results"""
    
    def __init__(self):
        self.entries: List[FeedbackEntry] = []
        self.stats = FeedbackStats()
        
        # Track by generation method
        self.method_stats: Dict[str, FeedbackStats] = {}
        
        # Track by confidence bucket
        self.confidence_buckets: Dict[str, FeedbackStats] = {
            '0.0-0.2': FeedbackStats(),
            '0.2-0.4': FeedbackStats(),
            '0.4-0.6': FeedbackStats(),
            '0.6-0.8': FeedbackStats(),
            '0.8-1.0': FeedbackStats(),
        }
    
    def add_feedback(
        self,
        address: str,
        predicted_active: bool,
        predicted_confidence: float,
        actual_active: bool,
        generation_method: str = "unknown"
    ):
        """Add a feedback entry"""
        entry = FeedbackEntry(
            address=address,
            predicted_active=predicted_active,
            predicted_confidence=predicted_confidence,
            actual_active=actual_active,
            generation_method=generation_method
        )
        
        self.entries.append(entry)
        self._update_stats(entry)
    
    def add_from_probe_results(
        self,
        generated_addresses: List[GeneratedAddress],
        probe_results: Dict[str, List[ProbeResponse]]
    ):
        """Add feedback from a batch of probe results"""
        # Create lookup for generated addresses
        gen_lookup = {g.address: g for g in generated_addresses}
        
        for address, responses in probe_results.items():
            gen_addr = gen_lookup.get(address)
            if not gen_addr:
                continue
            
            # Determine if active (any successful response)
            actual_active = any(r.result == ProbeResult.ACTIVE for r in responses)
            
            # Get prediction info
            predicted_active = gen_addr.confidence >= 0.5
            
            self.add_feedback(
                address=address,
                predicted_active=predicted_active,
                predicted_confidence=gen_addr.confidence,
                actual_active=actual_active,
                generation_method=gen_addr.generation_method
            )
    
    def _update_stats(self, entry: FeedbackEntry):
        """Update statistics with a new entry"""
        # Overall stats
        self._update_single_stats(self.stats, entry)
        
        # Method stats
        if entry.generation_method not in self.method_stats:
            self.method_stats[entry.generation_method] = FeedbackStats()
        self._update_single_stats(self.method_stats[entry.generation_method], entry)
        
        # Confidence bucket stats
        bucket = self._get_confidence_bucket(entry.predicted_confidence)
        self._update_single_stats(self.confidence_buckets[bucket], entry)
    
    def _update_single_stats(self, stats: FeedbackStats, entry: FeedbackEntry):
        """Update a single stats object"""
        stats.total_predictions += 1
        
        if entry.is_correct:
            stats.correct_predictions += 1
        
        if entry.predicted_active and entry.actual_active:
            stats.true_positives += 1
        elif entry.predicted_active and not entry.actual_active:
            stats.false_positives += 1
        elif not entry.predicted_active and entry.actual_active:
            stats.false_negatives += 1
        else:
            stats.true_negatives += 1
    
    def _get_confidence_bucket(self, confidence: float) -> str:
        """Get the bucket for a confidence value"""
        if confidence < 0.2:
            return '0.0-0.2'
        elif confidence < 0.4:
            return '0.2-0.4'
        elif confidence < 0.6:
            return '0.4-0.6'
        elif confidence < 0.8:
            return '0.6-0.8'
        else:
            return '0.8-1.0'
    
    def get_active_addresses(self) -> List[str]:
        """Get addresses that were actually active"""
        return [e.address for e in self.entries if e.actual_active]
    
    def get_inactive_addresses(self) -> List[str]:
        """Get addresses that were actually inactive"""
        return [e.address for e in self.entries if not e.actual_active]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all feedback"""
        return {
            'overall': self.stats.to_dict(),
            'by_method': {
                method: stats.to_dict()
                for method, stats in self.method_stats.items()
            },
            'by_confidence': {
                bucket: stats.to_dict()
                for bucket, stats in self.confidence_buckets.items()
            }
        }
    
    def save(self, filepath: Path):
        """Save feedback to file"""
        data = {
            'entries': [e.to_dict() for e in self.entries],
            'summary': self.get_summary()
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load(self, filepath: Path):
        """Load feedback from file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        self.entries = []
        self.stats = FeedbackStats()
        self.method_stats = {}
        
        for entry_data in data.get('entries', []):
            entry = FeedbackEntry(
                address=entry_data['address'],
                predicted_active=entry_data['predicted_active'],
                predicted_confidence=entry_data['predicted_confidence'],
                actual_active=entry_data['actual_active'],
                generation_method=entry_data['generation_method'],
                timestamp=datetime.fromisoformat(entry_data['timestamp'])
            )
            self.entries.append(entry)
            self._update_stats(entry)


class FeedbackLoop:
    """
    Implements closed-loop optimization for the IPv6 crawler.
    
    The feedback loop:
    1. Generates addresses using the ML model
    2. Probes them to determine actual state
    3. Collects feedback on predictions
    4. Retrains/updates the model periodically
    """
    
    def __init__(
        self,
        predictor: EnsembleIPv6Predictor,
        generator: SmartAddressGenerator,
        config: Optional[Dict[str, Any]] = None
    ):
        self.config = config or {}
        self.predictor = predictor
        self.generator = generator
        
        self.feedback_collector = FeedbackCollector()
        
        # Configuration
        self.retrain_threshold = self.config.get('retrain_threshold', 500)
        self.min_retrain_samples = self.config.get('min_retrain_samples', 100)
        
        # State
        self.samples_since_retrain = 0
        self.retrain_count = 0
        
    def record_feedback(
        self,
        generated_addresses: List[GeneratedAddress],
        probe_results: Dict[str, List[ProbeResponse]]
    ):
        """Record feedback from probe results"""
        self.feedback_collector.add_from_probe_results(
            generated_addresses, probe_results
        )
        
        # Update generator with results
        results = []
        gen_lookup = {g.address: g for g in generated_addresses}
        
        for address, responses in probe_results.items():
            gen_addr = gen_lookup.get(address)
            if gen_addr:
                actual_active = any(r.result == ProbeResult.ACTIVE for r in responses)
                results.append((gen_addr, actual_active))
        
        self.generator.update_from_results(results)
        
        # Update prefix predictor
        prefix_results = [
            (addr, any(r.result == ProbeResult.ACTIVE for r in responses))
            for addr, responses in probe_results.items()
        ]
        self.predictor.update_from_feedback(prefix_results)
        
        self.samples_since_retrain += len(probe_results)
        
        # Check if retraining is needed
        if self.should_retrain():
            self.retrain_model()
    
    def should_retrain(self) -> bool:
        """Check if the model should be retrained"""
        if self.samples_since_retrain < self.retrain_threshold:
            return False
        
        # Need enough samples for both classes
        active = len(self.feedback_collector.get_active_addresses())
        inactive = len(self.feedback_collector.get_inactive_addresses())
        
        return active >= self.min_retrain_samples and inactive >= self.min_retrain_samples
    
    def retrain_model(self) -> Dict[str, Any]:
        """Retrain the model with new feedback"""
        logger.info("Retraining model with feedback data...")
        
        active_addresses = self.feedback_collector.get_active_addresses()
        inactive_addresses = self.feedback_collector.get_inactive_addresses()
        
        logger.info(f"Training data: {len(active_addresses)} active, {len(inactive_addresses)} inactive")
        
        # Retrain
        stats = self.predictor.train(active_addresses, inactive_addresses)
        
        self.samples_since_retrain = 0
        self.retrain_count += 1
        
        logger.info(f"Model retrained (retrain #{self.retrain_count})")
        return stats
    
    def get_optimal_confidence_threshold(self) -> float:
        """
        Analyze feedback to find optimal confidence threshold.
        The goal is to maximize precision while maintaining reasonable recall.
        """
        if len(self.feedback_collector.entries) < 100:
            return 0.5  # Default
        
        # Try different thresholds
        thresholds = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
        best_threshold = 0.5
        best_score = 0.0
        
        for threshold in thresholds:
            tp = fp = fn = 0
            
            for entry in self.feedback_collector.entries:
                pred = entry.predicted_confidence >= threshold
                actual = entry.actual_active
                
                if pred and actual:
                    tp += 1
                elif pred and not actual:
                    fp += 1
                elif not pred and actual:
                    fn += 1
            
            # Calculate F1-like score with emphasis on precision
            if tp + fp > 0:
                precision = tp / (tp + fp)
            else:
                precision = 0
            
            if tp + fn > 0:
                recall = tp / (tp + fn)
            else:
                recall = 0
            
            # Weighted F-score (precision-biased)
            beta = 0.5  # Favor precision
            if precision + recall > 0:
                score = (1 + beta**2) * precision * recall / (beta**2 * precision + recall)
            else:
                score = 0
            
            if score > best_score:
                best_score = score
                best_threshold = threshold
        
        return best_threshold
    
    def get_method_recommendations(self) -> Dict[str, float]:
        """
        Analyze which generation methods work best.
        Returns weights for each method.
        """
        method_scores = {}
        
        for method, stats in self.feedback_collector.method_stats.items():
            if stats.total_predictions >= 10:
                # Use hit rate (precision) as the score
                method_scores[method] = stats.precision
        
        # Normalize to weights
        if method_scores:
            total = sum(method_scores.values())
            if total > 0:
                method_scores = {k: v / total for k, v in method_scores.items()}
        
        return method_scores
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate a performance report"""
        return {
            'overall_stats': self.feedback_collector.stats.to_dict(),
            'optimal_threshold': self.get_optimal_confidence_threshold(),
            'method_recommendations': self.get_method_recommendations(),
            'retrain_count': self.retrain_count,
            'samples_since_retrain': self.samples_since_retrain,
            'feedback_summary': self.feedback_collector.get_summary()
        }
    
    def save_state(self, directory: Path):
        """Save feedback loop state"""
        directory.mkdir(parents=True, exist_ok=True)
        
        # Save feedback
        self.feedback_collector.save(directory / "feedback.json")
        
        # Save state
        state = {
            'retrain_count': self.retrain_count,
            'samples_since_retrain': self.samples_since_retrain,
            'optimal_threshold': self.get_optimal_confidence_threshold()
        }
        with open(directory / "loop_state.json", 'w') as f:
            json.dump(state, f)
    
    def load_state(self, directory: Path):
        """Load feedback loop state"""
        feedback_file = directory / "feedback.json"
        if feedback_file.exists():
            self.feedback_collector.load(feedback_file)
        
        state_file = directory / "loop_state.json"
        if state_file.exists():
            with open(state_file, 'r') as f:
                state = json.load(f)
            self.retrain_count = state.get('retrain_count', 0)
            self.samples_since_retrain = state.get('samples_since_retrain', 0)


class AdaptiveFeedbackLoop(FeedbackLoop):
    """
    Enhanced feedback loop with adaptive strategies.
    
    Features:
    - Dynamic threshold adjustment
    - Exploration vs exploitation balance
    - Method weight updates
    """
    
    def __init__(
        self,
        predictor: EnsembleIPv6Predictor,
        generator: SmartAddressGenerator,
        config: Optional[Dict[str, Any]] = None
    ):
        super().__init__(predictor, generator, config)
        
        # Exploration parameters
        self.exploration_rate = 0.2  # Start with 20% exploration
        self.min_exploration = 0.05
        self.exploration_decay = 0.99
        
    def get_next_batch_strategy(self) -> Dict[str, Any]:
        """
        Determine strategy for next batch of addresses.
        Balances exploration (random/diverse) vs exploitation (ML-guided).
        """
        # Calculate exploitation portion
        exploitation_count = int((1 - self.exploration_rate) * 1000)
        exploration_count = 1000 - exploitation_count
        
        # Get method recommendations
        method_weights = self.get_method_recommendations()
        
        return {
            'exploitation_count': exploitation_count,
            'exploration_count': exploration_count,
            'min_confidence': self.get_optimal_confidence_threshold(),
            'method_weights': method_weights,
            'exploration_rate': self.exploration_rate
        }
    
    def update_exploration_rate(self):
        """Decay exploration rate over time"""
        self.exploration_rate = max(
            self.min_exploration,
            self.exploration_rate * self.exploration_decay
        )
    
    def record_feedback(
        self,
        generated_addresses: List[GeneratedAddress],
        probe_results: Dict[str, List[ProbeResponse]]
    ):
        """Record feedback and update exploration"""
        super().record_feedback(generated_addresses, probe_results)
        self.update_exploration_rate()


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Create mock components for testing
    print("Feedback Loop module loaded successfully")
    print("This module implements closed-loop optimization for the IPv6 crawler")
