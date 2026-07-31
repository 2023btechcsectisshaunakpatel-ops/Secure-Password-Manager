from datetime import datetime
try:
    from sqlalchemy import Column, Integer, String, DateTime
    from database import Base, HAS_SQLALCHEMY
except ImportError:
    from .database import Base, HAS_SQLALCHEMY

if HAS_SQLALCHEMY:
    class User(Base):
        __tablename__ = "users"

        id = Column(Integer, primary_key=True, index=True, autoincrement=True)
        email = Column(String, unique=True, index=True, nullable=False)
        hashed_password = Column(String, nullable=False)
        created_at = Column(DateTime, default=datetime.utcnow)

    class Entry(Base):
        __tablename__ = "entries"

        id = Column(Integer, primary_key=True, index=True, autoincrement=True)
        user_id = Column(Integer, index=True, nullable=False)
        site_name = Column(String, index=True, nullable=False)
        site_username = Column(String, nullable=False)
        encrypted_password = Column(String, nullable=False)
        nonce = Column(String, nullable=False)
        created_at = Column(DateTime, default=datetime.utcnow)
        updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
else:
    class User:
        pass
    class Entry:
        pass
