"""
Machine Learning Model Module
مدل‌های ML برای پیش‌بینی آدرس‌های IPv6 فعال
"""

import logging
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
import numpy as np
from datetime import datetime
import json
import joblib

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score
)
from sklearn.preprocessing import StandardScaler
import xgboost as xgb

from .feature_extractor import IPv6FeatureExtractor, IPv6Features

logger = logging.getLogger(__name__)


class IPv6ActivePredictor:
    """
    Machine Learning model to predict if an IPv6 address is likely active.
    
    Uses an ensemble of:
    - Random Forest
    - XGBoost
    - Gradient Boosting
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.feature_extractor = IPv6FeatureExtractor()
        self.scaler = StandardScaler()
        self.model = None
        self.is_trained = False
        self.training_stats = {}
        
        # Model parameters
        self.n_estimators = self.config.get('n_estimators', 100)
        self.random_state = self.config.get('random_state', 42)
        self.test_size = self.config.get('test_size', 0.2)
        
    def _create_ensemble_model(self):
        """Create the ensemble model"""
        # Random Forest
        rf = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=self.random_state,
            n_jobs=-1
        )
        
        # XGBoost
        xgb_clf = xgb.XGBClassifier(
            n_estimators=self.n_estimators,
            max_depth=10,
            learning_rate=0.1,
            random_state=self.random_state,
            use_label_encoder=False,
            eval_metric='logloss'
        )
        
        # Gradient Boosting
        gb = GradientBoostingClassifier(
            n_estimators=self.n_estimators // 2,  # Slower, so fewer estimators
            max_depth=8,
            learning_rate=0.1,
            random_state=self.random_state
        )
        
        # Ensemble with soft voting
        ensemble = VotingClassifier(
            estimators=[
                ('rf', rf),
                ('xgb', xgb_clf),
                ('gb', gb)
            ],
            voting='soft',
            weights=[2, 3, 1]  # XGBoost gets higher weight
        )
        
        return ensemble
    
    def prepare_training_data(
        self,
        active_addresses: List[str],
        inactive_addresses: List[str]
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data from active and inactive addresses"""
        logger.info(f"Preparing training data: {len(active_addresses)} active, {len(inactive_addresses)} inactive")
        
        # Extract features for active addresses
        X_active, valid_active = self.feature_extractor.extract_features_batch(active_addresses)
        y_active = np.ones(len(valid_active))
        
        # Extract features for inactive addresses
        X_inactive, valid_inactive = self.feature_extractor.extract_features_batch(inactive_addresses)
        y_inactive = np.zeros(len(valid_inactive))
        
        # Combine
        X = np.vstack([X_active, X_inactive])
        y = np.concatenate([y_active, y_inactive])
        
        # Shuffle
        indices = np.random.permutation(len(y))
        X = X[indices]
        y = y[indices]
        
        logger.info(f"Prepared {len(y)} samples for training")
        return X, y
    
    def train(
        self,
        active_addresses: List[str],
        inactive_addresses: List[str],
        validate: bool = True
    ) -> Dict[str, Any]:
        """Train the model on labeled data"""
        logger.info("Starting model training...")
        
        # Prepare data
        X, y = self.prepare_training_data(active_addresses, inactive_addresses)
        
        if len(X) < 10:
            raise ValueError("Not enough training data")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=y
        )
        
        # Create and train model
        self.model = self._create_ensemble_model()
        
        logger.info("Training ensemble model...")
        self.model.fit(X_train, y_train)
        
        # Evaluate if requested
        metrics = {}
        if validate:
            metrics = self._evaluate(X_test, y_test)
            
            # Cross-validation
            cv_scores = cross_val_score(self.model, X_scaled, y, cv=5, scoring='f1')
            metrics['cv_f1_mean'] = float(np.mean(cv_scores))
            metrics['cv_f1_std'] = float(np.std(cv_scores))
        
        self.is_trained = True
        self.training_stats = {
            'trained_at': datetime.now().isoformat(),
            'n_samples': len(y),
            'n_active': int(sum(y)),
            'n_inactive': int(len(y) - sum(y)),
            'metrics': metrics
        }
        
        logger.info(f"Training complete. F1 Score: {metrics.get('f1', 'N/A')}")
        return self.training_stats
    
    def _evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, float]:
        """Evaluate model on test data"""
        y_pred = self.model.predict(X_test)
        y_prob = self.model.predict_proba(X_test)[:, 1]
        
        metrics = {
            'accuracy': float(accuracy_score(y_test, y_pred)),
            'precision': float(precision_score(y_test, y_pred, zero_division=0)),
            'recall': float(recall_score(y_test, y_pred, zero_division=0)),
            'f1': float(f1_score(y_test, y_pred, zero_division=0)),
            'roc_auc': float(roc_auc_score(y_test, y_prob)),
        }
        
        logger.info("Model Evaluation Metrics:")
        for name, value in metrics.items():
            logger.info(f"  {name}: {value:.4f}")
        
        return metrics
    
    def predict(self, addresses: List[str]) -> List[Tuple[str, float, bool]]:
        """
        Predict if addresses are active.
        
        Returns: List of (address, probability, is_active_prediction)
        """
        if not self.is_trained:
            raise ValueError("Model not trained yet")
        
        # Extract features
        X, valid_addresses = self.feature_extractor.extract_features_batch(addresses)
        
        if len(X) == 0:
            return []
        
        # Scale
        X_scaled = self.scaler.transform(X)
        
        # Predict
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)[:, 1]
        
        results = []
        for addr, prob, pred in zip(valid_addresses, probabilities, predictions):
            results.append((addr, float(prob), bool(pred)))
        
        return results
    
    def predict_proba(self, addresses: List[str]) -> List[Tuple[str, float]]:
        """Get probability scores for addresses"""
        if not self.is_trained:
            raise ValueError("Model not trained yet")
        
        X, valid_addresses = self.feature_extractor.extract_features_batch(addresses)
        
        if len(X) == 0:
            return []
        
        X_scaled = self.scaler.transform(X)
        probabilities = self.model.predict_proba(X_scaled)[:, 1]
        
        return list(zip(valid_addresses, probabilities.tolist()))
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from the model"""
        if not self.is_trained:
            return {}
        
        # Try to get importance from Random Forest component
        try:
            rf = self.model.named_estimators_['rf']
            importances = rf.feature_importances_
            feature_names = self.feature_extractor.get_feature_importance_names()
            
            importance_dict = dict(zip(feature_names, importances.tolist()))
            # Sort by importance
            return dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True))
        except Exception as e:
            logger.warning(f"Could not get feature importance: {e}")
            return {}
    
    def save_model(self, filepath: Path):
        """Save the trained model"""
        if not self.is_trained:
            raise ValueError("No trained model to save")
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'config': self.config,
            'training_stats': self.training_stats,
            'is_trained': self.is_trained
        }
        
        joblib.dump(model_data, filepath)
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: Path):
        """Load a trained model"""
        if not filepath.exists():
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        model_data = joblib.load(filepath)
        
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.config = model_data['config']
        self.training_stats = model_data['training_stats']
        self.is_trained = model_data['is_trained']
        
        logger.info(f"Model loaded from {filepath}")


class PrefixBasedPredictor:
    """
    Predict active addresses based on prefix patterns.
    Learns which prefixes are more likely to have active hosts.
    """
    
    def __init__(self):
        self.prefix_stats: Dict[str, Dict[str, Any]] = {}
        self.overall_stats = {'total': 0, 'active': 0}
        
    def update_from_probe_results(
        self,
        results: List[Tuple[str, bool]]  # (address, is_active)
    ):
        """Update prefix statistics from probe results"""
        import ipaddress
        
        for address, is_active in results:
            try:
                # Get /48 prefix
                network = ipaddress.IPv6Network(f"{address}/48", strict=False)
                prefix = str(network.network_address)
                
                if prefix not in self.prefix_stats:
                    self.prefix_stats[prefix] = {'total': 0, 'active': 0}
                
                self.prefix_stats[prefix]['total'] += 1
                self.prefix_stats[prefix]['active'] += int(is_active)
                
                self.overall_stats['total'] += 1
                self.overall_stats['active'] += int(is_active)
            except:
                continue
    
    def get_prefix_score(self, address: str) -> float:
        """Get activity score for an address based on its prefix"""
        import ipaddress
        
        try:
            network = ipaddress.IPv6Network(f"{address}/48", strict=False)
            prefix = str(network.network_address)
            
            if prefix in self.prefix_stats:
                stats = self.prefix_stats[prefix]
                if stats['total'] > 0:
                    return stats['active'] / stats['total']
            
            # Fall back to overall rate
            if self.overall_stats['total'] > 0:
                return self.overall_stats['active'] / self.overall_stats['total']
            
        except:
            pass
        
        return 0.5  # Unknown
    
    def get_top_prefixes(self, n: int = 20) -> List[Tuple[str, float, int]]:
        """Get top N prefixes by activity rate"""
        prefix_scores = []
        
        for prefix, stats in self.prefix_stats.items():
            if stats['total'] >= 5:  # Minimum samples
                score = stats['active'] / stats['total']
                prefix_scores.append((prefix, score, stats['total']))
        
        # Sort by score
        prefix_scores.sort(key=lambda x: x[1], reverse=True)
        return prefix_scores[:n]


class EnsembleIPv6Predictor:
    """
    Combines multiple prediction strategies:
    1. ML-based prediction (feature-based)
    2. Prefix-based prediction (historical patterns)
    3. Pattern matching (known allocation patterns)
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.ml_predictor = IPv6ActivePredictor(config)
        self.prefix_predictor = PrefixBasedPredictor()
        
        # Weights for combining predictions
        self.ml_weight = 0.6
        self.prefix_weight = 0.3
        self.pattern_weight = 0.1
        
    def train(
        self,
        active_addresses: List[str],
        inactive_addresses: List[str]
    ) -> Dict[str, Any]:
        """Train the ensemble"""
        # Train ML model
        stats = self.ml_predictor.train(active_addresses, inactive_addresses)
        
        # Update prefix stats
        results = [(addr, True) for addr in active_addresses]
        results.extend([(addr, False) for addr in inactive_addresses])
        self.prefix_predictor.update_from_probe_results(results)
        
        return stats
    
    def predict_combined(self, addresses: List[str]) -> List[Tuple[str, float]]:
        """Get combined prediction scores"""
        results = []
        
        # Get ML predictions
        ml_predictions = {}
        if self.ml_predictor.is_trained:
            for addr, prob in self.ml_predictor.predict_proba(addresses):
                ml_predictions[addr] = prob
        
        # Combine with prefix scores
        for addr in addresses:
            ml_score = ml_predictions.get(addr, 0.5)
            prefix_score = self.prefix_predictor.get_prefix_score(addr)
            
            # Weighted combination
            combined = (
                self.ml_weight * ml_score +
                self.prefix_weight * prefix_score +
                self.pattern_weight * 0.5  # Placeholder for pattern matching
            )
            
            results.append((addr, combined))
        
        # Sort by score
        results.sort(key=lambda x: x[1], reverse=True)
        return results
    
    def update_from_feedback(self, results: List[Tuple[str, bool]]):
        """Update models from probe feedback"""
        self.prefix_predictor.update_from_probe_results(results)
        # Could also implement incremental ML updates here
    
    def save(self, directory: Path):
        """Save all models"""
        directory.mkdir(parents=True, exist_ok=True)
        
        if self.ml_predictor.is_trained:
            self.ml_predictor.save_model(directory / "ml_model.joblib")
        
        # Save prefix stats
        prefix_file = directory / "prefix_stats.json"
        with open(prefix_file, 'w') as f:
            json.dump({
                'prefix_stats': self.prefix_predictor.prefix_stats,
                'overall_stats': self.prefix_predictor.overall_stats
            }, f)
        
        logger.info(f"Ensemble saved to {directory}")
    
    def load(self, directory: Path):
        """Load all models"""
        ml_path = directory / "ml_model.joblib"
        if ml_path.exists():
            self.ml_predictor.load_model(ml_path)
        
        prefix_file = directory / "prefix_stats.json"
        if prefix_file.exists():
            with open(prefix_file, 'r') as f:
                data = json.load(f)
            self.prefix_predictor.prefix_stats = data.get('prefix_stats', {})
            self.prefix_predictor.overall_stats = data.get('overall_stats', {'total': 0, 'active': 0})
        
        logger.info(f"Ensemble loaded from {directory}")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Example: Create and test the predictor
    predictor = IPv6ActivePredictor()
    
    # Sample data (in real use, this would come from actual probing)
    active_sample = [
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
    ]
    
    inactive_sample = [
        "2001:db8::1",  # Documentation prefix
        "2001:db8::2",
        "2001:db8:1234::1",
    ]
    
    print("Note: This example requires more data for actual training.")
    print("In production, you need hundreds to thousands of labeled samples.")
