"""Load test suite for anti-scam API endpoints.

Run with: locust -f tests/load_test.py --host=http://localhost:7071

Requires: pip install locust
This module is skipped by pytest if locust is not installed.
"""

import pytest

try:
    from locust import HttpUser, task, between
except ImportError:
    pytest.skip("locust not installed", allow_module_level=True)


class AntiScamUser(HttpUser):
    wait_time = between(1, 3)

    @task(3)
    def classify(self):
        self.client.post("/api/classify", json={
            "text": "You have won a million dollars! Click here to claim your prize now.",
        })

    @task(2)
    def analyze(self):
        self.client.post("/api/analyze", json={
            "text": "Dear customer, your account has been compromised. Verify immediately.",
        })

    @task(1)
    def guidance(self):
        self.client.post("/api/guidance", json={
            "text": "IRS calling: pay your taxes immediately or face arrest.",
        })

    @task(1)
    def sentiment(self):
        self.client.post("/api/sentiment", json={
            "text": "URGENT: Your package is being held. Pay the fee NOW or it will be returned!",
        })

    @task(2)
    def health(self):
        self.client.get("/api/health")

    @task(1)
    def check_url(self):
        self.client.post("/api/check-url", json={
            "url": "https://example.com",
        })
