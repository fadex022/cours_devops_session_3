import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock
from datetime import datetime
from main import Item

def test_read_root(client: TestClient):
    """Test the root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello World - FastAPI with PostgreSQL"}

def test_health_check(client: TestClient):
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "database": "connected"}

def test_get_items_empty(client: TestClient, mock_db):
    """Test getting items when the database is empty."""
    # Setup mock
    mock_db.query.return_value.offset.return_value.limit.return_value.all.return_value = []
    
    # Test
    response = client.get("/items/")
    assert response.status_code == 200
    assert response.json() == []
    
    # Verify mock was called correctly
    mock_db.query.assert_called_once_with(Item)
    mock_db.query.return_value.offset.assert_called_once_with(0)
    mock_db.query.return_value.offset.return_value.limit.assert_called_once_with(100)

def test_get_items(client: TestClient, mock_db):
    """Test getting items with data."""
    # Create mock items
    mock_item1 = MagicMock()
    mock_item1.id = 1
    mock_item1.name = "Test Item 1"
    mock_item1.description = "Description 1"
    mock_item1.created_at = datetime.utcnow()
    
    mock_item2 = MagicMock()
    mock_item2.id = 2
    mock_item2.name = "Test Item 2"
    mock_item2.description = "Description 2"
    mock_item2.created_at = datetime.utcnow()
    
    # Setup mock
    mock_db.query.return_value.offset.return_value.limit.return_value.all.return_value = [mock_item1, mock_item2]
    
    # Test
    response = client.get("/items/")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert data[0]["id"] == 1
    assert data[0]["name"] == "Test Item 1"
    assert data[1]["id"] == 2
    assert data[1]["name"] == "Test Item 2"

def test_get_item(client: TestClient, mock_db):
    """Test getting a specific item by ID."""
    # Create mock item
    mock_item = MagicMock()
    mock_item.id = 1
    mock_item.name = "Test Item"
    mock_item.description = "Test Description"
    mock_item.created_at = datetime.utcnow()
    
    # Setup mock
    mock_db.query.return_value.filter.return_value.first.return_value = mock_item
    
    # Test
    response = client.get("/items/1")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == 1
    assert data["name"] == "Test Item"
    assert data["description"] == "Test Description"
    
    # Verify mock was called correctly
    mock_db.query.assert_called_once_with(Item)
    mock_db.query.return_value.filter.assert_called_once()

def test_get_item_not_found(client: TestClient, mock_db):
    """Test getting a non-existent item."""
    # Setup mock
    mock_db.query.return_value.filter.return_value.first.return_value = None
    
    # Test
    response = client.get("/items/999")
    assert response.status_code == 404
    assert response.json() == {"detail": "Item not found"}

def test_create_item(client: TestClient, mock_db):
    """Test creating a new item."""
    # Create mock item
    mock_item = MagicMock()
    mock_item.id = 1
    mock_item.name = "New Item"
    mock_item.description = "New Description"
    mock_item.created_at = datetime.utcnow()
    
    # Setup mock to return our mock item after commit
    def side_effect(item):
        item.id = 1
        item.created_at = datetime.utcnow()
        return item
    
    mock_db.add.side_effect = lambda x: None
    mock_db.commit.side_effect = lambda: None
    mock_db.refresh.side_effect = side_effect
    
    # Test
    item_data = {"name": "New Item", "description": "New Description"}
    response = client.post("/items/", json=item_data)
    
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "New Item"
    assert data["description"] == "New Description"
    assert "id" in data
    assert "created_at" in data
    
    # Verify mock was called correctly
    mock_db.add.assert_called_once()
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once()

def test_update_item(client: TestClient, mock_db):
    """Test updating an item."""
    # Create mock item
    mock_item = MagicMock()
    mock_item.id = 1
    mock_item.name = "Original Name"
    mock_item.description = "Original Description"
    mock_item.created_at = datetime.utcnow()
    
    # Setup mock
    mock_db.query.return_value.filter.return_value.first.return_value = mock_item
    
    # Test
    updated_data = {"name": "Updated Name", "description": "Updated Description"}
    response = client.put("/items/1", json=updated_data)
    
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == 1
    assert data["name"] == "Updated Name"
    assert data["description"] == "Updated Description"
    
    # Verify mock was called correctly
    mock_db.query.assert_called_once_with(Item)
    mock_db.query.return_value.filter.assert_called_once()
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once()

def test_update_item_not_found(client: TestClient, mock_db):
    """Test updating a non-existent item."""
    # Setup mock
    mock_db.query.return_value.filter.return_value.first.return_value = None
    
    # Test
    updated_data = {"name": "Updated Name", "description": "Updated Description"}
    response = client.put("/items/999", json=updated_data)
    
    assert response.status_code == 404
    assert response.json() == {"detail": "Item not found"}

def test_delete_item(client: TestClient, mock_db):
    """Test deleting an item."""
    # Create mock item
    mock_item = MagicMock()
    mock_item.id = 1
    
    # Setup mock
    mock_db.query.return_value.filter.return_value.first.return_value = mock_item
    
    # Test
    response = client.delete("/items/1")
    
    assert response.status_code == 200
    assert response.json() == {"message": "Item deleted successfully"}
    
    # Verify mock was called correctly
    mock_db.query.assert_called_once_with(Item)
    mock_db.query.return_value.filter.assert_called_once()
    mock_db.delete.assert_called_once_with(mock_item)
    mock_db.commit.assert_called_once()

def test_delete_item_not_found(client: TestClient, mock_db):
    """Test deleting a non-existent item."""
    # Setup mock
    mock_db.query.return_value.filter.return_value.first.return_value = None
    
    # Test
    response = client.delete("/items/999")
    
    assert response.status_code == 404
    assert response.json() == {"detail": "Item not found"}
