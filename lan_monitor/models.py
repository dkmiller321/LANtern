"""
Database models for LAN Monitor.

This module defines the SQLAlchemy ORM models for the LAN Monitor application.
"""

import datetime
from typing import List, Optional
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, Session
from pathlib import Path

from lan_monitor.config import config

Base = declarative_base()


class Device(Base):
    """Model representing a network device."""
    
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True)
    mac_address = Column(String, unique=True, index=True, nullable=False)
    ip_address = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    is_online = Column(Boolean, default=True)
    
    # Relationship with DeviceHistory
    history = relationship("DeviceHistory", back_populates="device", cascade="all, delete-orphan")
    
    def __repr__(self) -> str:
        """String representation of the Device."""
        return f"<Device(mac='{self.mac_address}', ip='{self.ip_address}', online={self.is_online})>"


class DeviceHistory(Base):
    """Model representing device connection history."""
    
    __tablename__ = "device_history"
    
    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    event_type = Column(String, nullable=False)  # "join" or "leave"
    ip_address = Column(String, nullable=True)
    
    # Relationship with Device
    device = relationship("Device", back_populates="history")
    
    def __repr__(self) -> str:
        """String representation of the DeviceHistory."""
        return f"<DeviceHistory(device_id={self.device_id}, event='{self.event_type}', time='{self.timestamp}')>"


class Database:
    """Database manager for LAN Monitor."""
    
    _instance = None
    
    def __new__(cls, db_path: Optional[str] = None):
        """Implement singleton pattern for Database class."""
        if cls._instance is None:
            cls._instance = super(Database, cls).__new__(cls)
            cls._instance._initialize(db_path)
        return cls._instance
    
    def _initialize(self, db_path: Optional[str] = None) -> None:
        """
        Initialize the database connection.
        
        Args:
            db_path: Path to the database file. If None, uses the path from config.
        """
        if db_path is None:
            db_type = config.get("database", "type", "sqlite")
            db_path = config.get("database", "path", "data/devices.db")
            
            # Get the project root directory
            root_dir = Path(__file__).parent.parent
            db_path = root_dir / db_path
            
            # Ensure the directory exists
            db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create the database engine
        self.engine = create_engine(f"sqlite:///{db_path}")
        
        # Create the session factory
        self.Session = sessionmaker(bind=self.engine)
        
        # Create tables if they don't exist
        Base.metadata.create_all(self.engine)
    
    def get_session(self) -> Session:
        """
        Get a database session.
        
        Returns:
            SQLAlchemy session object
        """
        return self.Session()
    
    def get_all_devices(self) -> List[Device]:
        """
        Get all devices from the database.
        
        Returns:
            List of Device objects
        """
        with self.get_session() as session:
            return session.query(Device).all()
    
    def get_online_devices(self) -> List[Device]:
        """
        Get all online devices from the database.
        
        Returns:
            List of online Device objects
        """
        with self.get_session() as session:
            return session.query(Device).filter(Device.is_online == True).all()
    
    def get_device_by_mac(self, mac_address: str) -> Optional[Device]:
        """
        Get a device by MAC address.
        
        Args:
            mac_address: MAC address of the device
            
        Returns:
            Device object or None if not found
        """
        with self.get_session() as session:
            return session.query(Device).filter(Device.mac_address == mac_address).first()
    
    def get_device_history(self, device_id: int, limit: int = 100) -> List[DeviceHistory]:
        """
        Get history for a device.
        
        Args:
            device_id: ID of the device
            limit: Maximum number of history entries to return
            
        Returns:
            List of DeviceHistory objects
        """
        with self.get_session() as session:
            return session.query(DeviceHistory)\
                .filter(DeviceHistory.device_id == device_id)\
                .order_by(DeviceHistory.timestamp.desc())\
                .limit(limit)\
                .all()


# Create a global instance for easy importing
db = Database()
