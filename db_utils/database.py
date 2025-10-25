import psycopg2
from psycopg2.extras import RealDictCursor

db_url = "postgresql://postgres:123456@localhost:5432/event_manager"
# engine = create_engine(db_url)
# session = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_connection():
    conn = psycopg2.connect(db_url, cursor_factory=RealDictCursor)
    return conn