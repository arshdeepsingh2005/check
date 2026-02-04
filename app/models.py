"""
Database models aligned with the legacy FastAPI service.
"""
from sqlalchemy import Column, Integer, String, Float

from app.database import Base


class User(Base):
    """
    Minimal user representation sourced from public.app_users.
    """

    __tablename__ = "app_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    usd_claim_amount = Column(Float, nullable=False, default=0.0)


class ExchangeRate(Base):
    """
    Stores exchange rates relative to USD.
    Example: 1 USD = rate * target_currency
    """

    __tablename__ = "exchange_rates"

    id = Column(Integer, primary_key=True, index=True)
    target_currency = Column(String(10), nullable=False, index=True)  # ISO code like INR, EUR
    rate_from_usd = Column(Float, nullable=False)

