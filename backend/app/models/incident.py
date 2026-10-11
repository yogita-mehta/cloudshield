from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text
from app.db.session import Base

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    classification = Column(String(50), default="NORMAL", nullable=False) # NORMAL, SUSPICIOUS, ATTACK, FLASH_CROWD
    mitigation_tier = Column(String(50), default="NONE", nullable=False)  # NONE, TIER_1, TIER_2, TIER_3, TIER_4
    source_ip = Column(String(50), nullable=True)
    requests_per_sec = Column(Float, default=0.0)
    baseline_rps = Column(Float, default=0.0)
    url_entropy = Column(Float, default=0.0)
    ip_entropy = Column(Float, default=0.0)
    verdict_reason = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "classification": self.classification,
            "mitigation_tier": self.mitigation_tier,
            "source_ip": self.source_ip,
            "requests_per_sec": self.requests_per_sec,
            "baseline_rps": self.baseline_rps,
            "url_entropy": self.url_entropy,
            "ip_entropy": self.ip_entropy,
            "verdict_reason": self.verdict_reason,
            "is_active": self.is_active,
        }
