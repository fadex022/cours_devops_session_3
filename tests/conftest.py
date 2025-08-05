import pytest
from fastapi.testclient import TestClient
import sys
import os
from unittest.mock import MagicMock, patch
from datetime import datetime

# Add the parent directory to sys.path to allow importing from main
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from main import app, get_db, Item

# Create a fixture for the test client
@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)

# Create a fixture for mocking the database session
@pytest.fixture
def mock_db():
    """Create a mock database session."""
    mock = MagicMock()
    
    # Override the get_db dependency
    app.dependency_overrides[get_db] = lambda: mock
    
    yield mock
    
    # Remove the override after the test
    app.dependency_overrides.clear()
