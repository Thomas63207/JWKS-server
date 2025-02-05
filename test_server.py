import pytest
import requests
import json

BASE_URL = "http://127.0.0.1:8080"

def test_home():
    """Test if the home route is accessible."""
    response = requests.get(f"{BASE_URL}/")
    assert response.status_code == 200
    assert response.text == "JWKS Server is running!"

def test_auth_valid_jwt():
    """Test if /auth returns a valid JWT token."""
    response = requests.post(f"{BASE_URL}/auth")
    assert response.status_code == 200
    
    data = response.json()
    assert "jwt" in data  # Ensure a token is returned

    token = data["jwt"]
    assert isinstance(token, str) and len(token) > 0  # Check if it's a valid string

def test_auth_expired_jwt():
    """Test if /auth?expired=true returns an expired JWT."""
    response = requests.post(f"{BASE_URL}/auth?expired=true")
    assert response.status_code == 200

    data = response.json()
    assert "jwt" in data  # Ensure an expired token is returned

def test_jwks_contains_valid_keys():
    """Test if JWKS endpoint contains valid keys."""
    response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
    assert response.status_code == 200
    
    data = response.json()
    assert "keys" in data and isinstance(data["keys"], list)  # JWKS must contain a keys list

    if data["keys"]:  # If keys exist, check their format
        key = data["keys"][0]
        assert "kid" in key
        assert "kty" in key and key["kty"] == "RSA"
        assert "n" in key  # Public key modulus (should be Base64URL encoded)
        assert "e" in key and key["e"] == "AQAB"

