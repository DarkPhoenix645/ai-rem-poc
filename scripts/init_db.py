#!/usr/bin/env python3
"""
Initialize the database with tables.
Run this after setting up PostgreSQL.
"""

import asyncio
import sys
from sqlalchemy.ext.asyncio import create_async_engine
from app.database.models import Base
from app.config import get_settings

async def init_database():
    """Create all database tables"""
    settings = get_settings()
    
    # Create async engine
    engine = create_async_engine(
        settings.database_url.replace("postgresql://", "postgresql+asyncpg://"),
        echo=True
    )
    
    try:
        # Create all tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        print("✅ Database tables created successfully")
        
    except Exception as e:
        print(f"❌ Failed to create database tables: {e}")
        sys.exit(1)
    
    finally:
        await engine.dispose()

if __name__ == "__main__":
    asyncio.run(init_database())
