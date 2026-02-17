"""
Database Module
مدیریت ذخیره‌سازی داده‌ها
"""

import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime
import json

from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean, 
    DateTime, Text, ForeignKey, JSON, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.pool import StaticPool

logger = logging.getLogger(__name__)

Base = declarative_base()


class SeedAddressModel(Base):
    """Database model for seed addresses"""
    __tablename__ = 'seed_addresses'
    
    id = Column(Integer, primary_key=True)
    address = Column(String(45), unique=True, nullable=False, index=True)
    source = Column(String(50))
    domain = Column(String(255))
    discovered_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean)
    metadata_json = Column(Text)
    
    # Index for faster lookups
    __table_args__ = (
        Index('idx_source', 'source'),
        Index('idx_active', 'is_active'),
    )


class ProbeResultModel(Base):
    """Database model for probe results"""
    __tablename__ = 'probe_results'
    
    id = Column(Integer, primary_key=True)
    address = Column(String(45), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    result = Column(String(20))  # active, inactive, timeout, error
    response_time_ms = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    http_status = Column(Integer)
    server_header = Column(String(255))
    error_message = Column(Text)
    ssl_info_json = Column(Text)
    
    __table_args__ = (
        Index('idx_address_port', 'address', 'port'),
        Index('idx_result', 'result'),
    )


class FingerprintModel(Base):
    """Database model for infrastructure fingerprints"""
    __tablename__ = 'fingerprints'
    
    id = Column(Integer, primary_key=True)
    address = Column(String(45), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_web_server = Column(Boolean)
    http_port_open = Column(Boolean)
    https_port_open = Column(Boolean)
    server_software = Column(String(255))
    powered_by = Column(String(255))
    detected_tech_json = Column(Text)
    cdn_provider = Column(String(50))
    is_behind_cdn = Column(Boolean)
    cdn_confidence = Column(Float)
    security_headers_json = Column(Text)
    ssl_info_json = Column(Text)
    http_status = Column(Integer)
    redirects_to_https = Column(Boolean)
    response_time_ms = Column(Float)
    
    __table_args__ = (
        Index('idx_cdn', 'cdn_provider'),
        Index('idx_web_server', 'is_web_server'),
    )


class GeneratedAddressModel(Base):
    """Database model for generated addresses"""
    __tablename__ = 'generated_addresses'
    
    id = Column(Integer, primary_key=True)
    address = Column(String(45), nullable=False, index=True)
    generation_method = Column(String(50))
    confidence = Column(Float)
    source_prefix = Column(String(50))
    source_address = Column(String(45))
    generated_at = Column(DateTime, default=datetime.utcnow)
    was_probed = Column(Boolean, default=False)
    probe_result = Column(String(20))
    
    __table_args__ = (
        Index('idx_method', 'generation_method'),
        Index('idx_confidence', 'confidence'),
    )


class FeedbackEntryModel(Base):
    """Database model for feedback entries"""
    __tablename__ = 'feedback_entries'
    
    id = Column(Integer, primary_key=True)
    address = Column(String(45), nullable=False, index=True)
    predicted_active = Column(Boolean)
    predicted_confidence = Column(Float)
    actual_active = Column(Boolean)
    generation_method = Column(String(50))
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_correct = Column(Boolean)
    
    __table_args__ = (
        Index('idx_correct', 'is_correct'),
        Index('idx_method_feedback', 'generation_method'),
    )


class CrawlerDatabase:
    """
    Main database interface for the IPv6 crawler.
    Uses SQLite for simplicity, can be extended to PostgreSQL for production.
    """
    
    def __init__(self, db_path: str = "data/ipv6_crawler.db"):
        self.db_path = db_path
        
        # Create directory if needed
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Create engine
        self.engine = create_engine(
            f"sqlite:///{db_path}",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False
        )
        
        # Create tables
        Base.metadata.create_all(self.engine)
        
        # Create session factory
        self.Session = sessionmaker(bind=self.engine)
        
        logger.info(f"Database initialized: {db_path}")
    
    def get_session(self):
        """Get a new database session"""
        return self.Session()
    
    # ==================== Seed Addresses ====================
    
    def add_seed(
        self,
        address: str,
        source: str,
        domain: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> bool:
        """Add a seed address"""
        session = self.get_session()
        try:
            # Check if exists
            existing = session.query(SeedAddressModel).filter_by(address=address).first()
            if existing:
                return False
            
            seed = SeedAddressModel(
                address=address,
                source=source,
                domain=domain,
                metadata_json=json.dumps(metadata) if metadata else None
            )
            session.add(seed)
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            logger.error(f"Error adding seed: {e}")
            return False
        finally:
            session.close()
    
    def add_seeds_batch(self, seeds: List[Dict[str, Any]]) -> int:
        """Add multiple seeds in a batch"""
        session = self.get_session()
        added = 0
        try:
            for seed_data in seeds:
                existing = session.query(SeedAddressModel).filter_by(
                    address=seed_data['address']
                ).first()
                
                if not existing:
                    seed = SeedAddressModel(
                        address=seed_data['address'],
                        source=seed_data.get('source', 'unknown'),
                        domain=seed_data.get('domain'),
                        metadata_json=json.dumps(seed_data.get('metadata'))
                    )
                    session.add(seed)
                    added += 1
            
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Error adding seeds batch: {e}")
        finally:
            session.close()
        
        return added
    
    def get_seeds(
        self,
        source: Optional[str] = None,
        is_active: Optional[bool] = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Get seed addresses with optional filters"""
        session = self.get_session()
        try:
            query = session.query(SeedAddressModel)
            
            if source:
                query = query.filter_by(source=source)
            if is_active is not None:
                query = query.filter_by(is_active=is_active)
            
            query = query.limit(limit)
            
            results = []
            for seed in query.all():
                results.append({
                    'address': seed.address,
                    'source': seed.source,
                    'domain': seed.domain,
                    'discovered_at': seed.discovered_at.isoformat() if seed.discovered_at else None,
                    'is_active': seed.is_active,
                    'metadata': json.loads(seed.metadata_json) if seed.metadata_json else None
                })
            
            return results
        finally:
            session.close()
    
    def update_seed_activity(self, address: str, is_active: bool):
        """Update whether a seed is active"""
        session = self.get_session()
        try:
            seed = session.query(SeedAddressModel).filter_by(address=address).first()
            if seed:
                seed.is_active = is_active
                session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Error updating seed: {e}")
        finally:
            session.close()
    
    # ==================== Probe Results ====================
    
    def add_probe_result(
        self,
        address: str,
        port: int,
        result: str,
        response_time_ms: float,
        http_status: Optional[int] = None,
        server_header: Optional[str] = None,
        error_message: Optional[str] = None,
        ssl_info: Optional[Dict] = None
    ):
        """Add a probe result"""
        session = self.get_session()
        try:
            probe = ProbeResultModel(
                address=address,
                port=port,
                result=result,
                response_time_ms=response_time_ms,
                http_status=http_status,
                server_header=server_header,
                error_message=error_message,
                ssl_info_json=json.dumps(ssl_info) if ssl_info else None
            )
            session.add(probe)
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Error adding probe result: {e}")
        finally:
            session.close()
    
    def get_active_addresses(self, limit: int = 10000) -> List[str]:
        """Get addresses that have been probed active"""
        session = self.get_session()
        try:
            results = session.query(ProbeResultModel.address).filter_by(
                result='active'
            ).distinct().limit(limit).all()
            
            return [r[0] for r in results]
        finally:
            session.close()
    
    def get_inactive_addresses(self, limit: int = 10000) -> List[str]:
        """Get addresses that have been probed inactive"""
        session = self.get_session()
        try:
            # Get addresses that were never active
            active_subquery = session.query(ProbeResultModel.address).filter_by(
                result='active'
            ).distinct()
            
            results = session.query(ProbeResultModel.address).filter(
                ~ProbeResultModel.address.in_(active_subquery)
            ).distinct().limit(limit).all()
            
            return [r[0] for r in results]
        finally:
            session.close()
    
    # ==================== Fingerprints ====================
    
    def add_fingerprint(self, fingerprint_data: Dict[str, Any]):
        """Add or update a fingerprint"""
        session = self.get_session()
        try:
            existing = session.query(FingerprintModel).filter_by(
                address=fingerprint_data['address']
            ).first()
            
            if existing:
                # Update
                for key, value in fingerprint_data.items():
                    if key == 'detected_tech':
                        setattr(existing, 'detected_tech_json', json.dumps(value))
                    elif key == 'security_headers':
                        setattr(existing, 'security_headers_json', json.dumps(value))
                    elif key == 'ssl_info':
                        setattr(existing, 'ssl_info_json', json.dumps(value))
                    elif hasattr(existing, key):
                        setattr(existing, key, value)
            else:
                # Create new
                fp = FingerprintModel(
                    address=fingerprint_data['address'],
                    is_web_server=fingerprint_data.get('is_web_server'),
                    http_port_open=fingerprint_data.get('http_port_open'),
                    https_port_open=fingerprint_data.get('https_port_open'),
                    server_software=fingerprint_data.get('server_software'),
                    powered_by=fingerprint_data.get('powered_by'),
                    detected_tech_json=json.dumps(fingerprint_data.get('detected_tech', [])),
                    cdn_provider=fingerprint_data.get('cdn_provider'),
                    is_behind_cdn=fingerprint_data.get('is_behind_cdn'),
                    cdn_confidence=fingerprint_data.get('cdn_confidence'),
                    security_headers_json=json.dumps(fingerprint_data.get('security_headers', {})),
                    ssl_info_json=json.dumps(fingerprint_data.get('ssl_info', {})),
                    http_status=fingerprint_data.get('http_status'),
                    redirects_to_https=fingerprint_data.get('redirects_to_https'),
                    response_time_ms=fingerprint_data.get('response_time_ms')
                )
                session.add(fp)
            
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Error adding fingerprint: {e}")
        finally:
            session.close()
    
    def get_fingerprint_stats(self) -> Dict[str, Any]:
        """Get fingerprint statistics"""
        session = self.get_session()
        try:
            total = session.query(FingerprintModel).count()
            web_servers = session.query(FingerprintModel).filter_by(is_web_server=True).count()
            https = session.query(FingerprintModel).filter_by(https_port_open=True).count()
            cdn = session.query(FingerprintModel).filter_by(is_behind_cdn=True).count()
            
            return {
                'total': total,
                'web_servers': web_servers,
                'https_enabled': https,
                'behind_cdn': cdn
            }
        finally:
            session.close()
    
    # ==================== Generated Addresses ====================
    
    def add_generated_addresses(self, addresses: List[Dict[str, Any]]) -> int:
        """Add generated addresses"""
        session = self.get_session()
        added = 0
        try:
            for addr_data in addresses:
                gen = GeneratedAddressModel(
                    address=addr_data['address'],
                    generation_method=addr_data.get('generation_method'),
                    confidence=addr_data.get('confidence'),
                    source_prefix=addr_data.get('source_prefix'),
                    source_address=addr_data.get('source_address')
                )
                session.add(gen)
                added += 1
            
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Error adding generated addresses: {e}")
        finally:
            session.close()
        
        return added
    
    def mark_addresses_probed(
        self,
        addresses: List[str],
        results: Dict[str, str]
    ):
        """Mark addresses as probed with their results"""
        session = self.get_session()
        try:
            for address in addresses:
                gen = session.query(GeneratedAddressModel).filter_by(
                    address=address, was_probed=False
                ).first()
                
                if gen:
                    gen.was_probed = True
                    gen.probe_result = results.get(address, 'unknown')
            
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Error marking addresses probed: {e}")
        finally:
            session.close()
    
    def get_unprobed_addresses(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Get addresses that haven't been probed yet"""
        session = self.get_session()
        try:
            results = session.query(GeneratedAddressModel).filter_by(
                was_probed=False
            ).order_by(GeneratedAddressModel.confidence.desc()).limit(limit).all()
            
            return [
                {
                    'address': r.address,
                    'generation_method': r.generation_method,
                    'confidence': r.confidence
                }
                for r in results
            ]
        finally:
            session.close()
    
    # ==================== Feedback ====================
    
    def add_feedback(
        self,
        address: str,
        predicted_active: bool,
        predicted_confidence: float,
        actual_active: bool,
        generation_method: str
    ):
        """Add feedback entry"""
        session = self.get_session()
        try:
            entry = FeedbackEntryModel(
                address=address,
                predicted_active=predicted_active,
                predicted_confidence=predicted_confidence,
                actual_active=actual_active,
                generation_method=generation_method,
                is_correct=predicted_active == actual_active
            )
            session.add(entry)
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Error adding feedback: {e}")
        finally:
            session.close()
    
    def get_feedback_stats(self) -> Dict[str, Any]:
        """Get feedback statistics"""
        session = self.get_session()
        try:
            total = session.query(FeedbackEntryModel).count()
            correct = session.query(FeedbackEntryModel).filter_by(is_correct=True).count()
            
            return {
                'total': total,
                'correct': correct,
                'accuracy': correct / total if total > 0 else 0
            }
        finally:
            session.close()
    
    # ==================== Utilities ====================
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall database statistics"""
        session = self.get_session()
        try:
            return {
                'seeds': session.query(SeedAddressModel).count(),
                'probe_results': session.query(ProbeResultModel).count(),
                'fingerprints': session.query(FingerprintModel).count(),
                'generated_addresses': session.query(GeneratedAddressModel).count(),
                'feedback_entries': session.query(FeedbackEntryModel).count(),
                'active_addresses': len(self.get_active_addresses(limit=100000))
            }
        finally:
            session.close()
    
    def export_to_json(self, filepath: Path):
        """Export all data to JSON"""
        data = {
            'seeds': self.get_seeds(limit=100000),
            'active_addresses': self.get_active_addresses(),
            'statistics': self.get_statistics()
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info(f"Exported database to {filepath}")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    db = CrawlerDatabase("test_crawler.db")
    
    # Add some test seeds
    db.add_seed("2001:4860:4860::8888", "dns", "google.com")
    db.add_seed("2606:4700:4700::1111", "dns", "cloudflare.com")
    
    # Get statistics
    print("Database Statistics:", db.get_statistics())
