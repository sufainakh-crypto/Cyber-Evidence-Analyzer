import os
from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Load environment variables from .env (future API keys, etc.)
load_dotenv()

# SQLite database file path (inside backend folder)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SQLITE_DB = os.path.join(BASE_DIR, "evidence.db")

# Create SQLAlchemy engine
engine = create_engine(f"sqlite:///{SQLITE_DB}", connect_args={"check_same_thread": False})

# SessionLocal will be used for DB sessions
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()

def init_db():
    Base.metadata.create_all(bind=engine)
    try:
        with engine.connect() as conn:
            result = conn.execute(text("PRAGMA table_info(evidence)"))
            columns = [row[1] for row in result.fetchall()]
            if "threat_intelligence_sources" not in columns:
                conn.execute(text("ALTER TABLE evidence ADD COLUMN threat_intelligence_sources TEXT"))
            if "threat_intelligence_summary" not in columns:
                conn.execute(text("ALTER TABLE evidence ADD COLUMN threat_intelligence_summary TEXT"))
            conn.commit()
    except Exception:
        pass
