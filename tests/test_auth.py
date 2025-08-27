import pytest
from fastapi.testclient import TestClient
from app.main import app

@pytest.fixture
def user_data():
    return {
        "email": "test@example.com",
        "username": "testuser",
        "password": "securepassword"
    }


def test_register_user(client, user_data):
    response = client.post("/auth/register", json=user_data)
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["email"] == user_data["email"]
    assert data["username"] == user_data["username"]


def test_register_user_duplicate(client,user_data):
    client.post("/auth/register", json=user_data)
    response = client.post("/auth/register", json=user_data)
    assert response.status_code == 400
    assert response.json()["detail"] == "User already exists"


def test_login_user(client,user_data):
    client.post("/auth/register", json=user_data)
    response = client.post(
        "/auth/login",
        data={
            "username": user_data["email"],
            "password": user_data["password"]
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data


def test_login_wrong_password(client,user_data):
    client.post("/auth/register", json=user_data)
    response = client.post(
        "/auth/login",
        data={"username": user_data["email"], "password": "wrongpassword"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_get_me(client,user_data):
    client.post("/auth/register", json=user_data)
    login_resp = client.post(
        "/auth/login",
        data={"username": user_data["email"], "password": user_data["password"]},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    token = login_resp.json()["access_token"]

    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == user_data["email"]


def test_refresh_token(client, user_data):
    client.post("/auth/register", json=user_data)
    login_resp = client.post(
        "/auth/login",
        data={"username": user_data["email"], "password": user_data["password"]},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    refresh = login_resp.json()["refresh_token"]
    assert refresh
    import time
    #FIXME ну это совсем неадекватное решение, я убил на это ПЯТЬ ЧАСОВ! не хочу искать изящное решение
    time.sleep(1)
    response = client.post("/auth/refresh", json={"refresh_token": refresh})
    assert response.status_code == 200
    data = response.json()
    print(data)
    assert "access_token" in data
    assert data["access_token"] != login_resp.json()["access_token"]
