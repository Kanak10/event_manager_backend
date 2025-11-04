# **🎟️ Event Management Backend**

This is the backend service for the Event Management system, built using FastAPI and Uvicorn (uv) for an efficient, modern, and asynchronous Python API.
It manages core operations such as user authentication, event handling, and chatbot interactions.

# **🚀 Tech Stack**
- FastAPI – High-performance Python web framework
- Uvicorn (uv) – ASGI server for running the application
- Alembic – Database migration tool
- SQLAlchemy – ORM for database operations
- Python 3.8+

# **🛠️ Project Setup**
### **1. Clone the Repository**
   
   ```
   git clone git@github.com:Kanak10/event_manager_backend.git
   cd event-management-backend
   ```
### **2. Install Dependencies**

We use uv for managing the environment and dependencies.
Initialize and synchronize your environment:
   ```
   uv sync
   ```
If a Python version mismatch occurs, ensure you have a compatible version and reinitialize:
   ```
   python -m uv init
   ```
### **3. Running the application:**
To start the FastAPI server in development mode:
   ```
   uvicorn main:app --reload
   ```

# **🗃️ Database Migrations**

We use Alembic for version-controlled database migrations.

### **1. Create a New Migration**
Navigate to the db_utils directory:
   ```
   cd db_utils
   ```
Generate a new migration:
   ```
   alembic revision --autogenerate -m "<comment>"
   ```
If a Python version mismatch occurs, use:
   ```
   python -m alembic revision --autogenerate -m "<comment>"
   ```

### **2. Apply Migrations**
After creating or pulling migration scripts, apply them using:
   ```
   alembic upgrade head
   ```
Or, if needed:
   ```
   python -m alembic upgrade head
   ```

