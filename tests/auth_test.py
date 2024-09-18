# import pytest
# from fastapi.testclient import TestClient
# from unittest.mock import patch
# from main import app, setup_logger
# import logging

# @pytest.fixture(scope="module")
# def client():
#     app.logger = setup_logger()
#     with TestClient(app) as c:
#         yield c

# def test_health_check(client):
#     response = client.get("/health")
#     assert response.status_code == 200
#     # Check if the response contains the expected keys
#     assert "status" in response.json()
#     assert response.json()["status"] == "healthy"
#     assert "uptime" in response.json()
#     assert "version" in response.json()
#     assert "total_routes" in response.json()
#     assert "app_name" in response.json()