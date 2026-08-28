from .models import FileArtifact as FileArtifact
from .models import MatchEvent as MatchEvent
from .models import ScanJob as ScanJob
from .session import Base, engine
from .session import SessionLocal as SessionLocal
from .session import get_db as get_db

# Create all tables in the engine.
# This is equivalent to "Create Table" statements in raw SQL.
# In a real production app, we would use Alembic instead, but this is good for bootstrapping.
Base.metadata.create_all(bind=engine)
