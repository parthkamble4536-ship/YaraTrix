from .session import engine, SessionLocal, Base, get_db
from .models import ScanJob, FileArtifact, MatchEvent

# Create all tables in the engine. 
# This is equivalent to "Create Table" statements in raw SQL.
# In a real production app, we would use Alembic instead, but this is good for bootstrapping.
Base.metadata.create_all(bind=engine)
