#!/usr/bin/env python3
"""
Quick test script to verify all /api/chat routing paths work.
Run this locally while func host is running on port 7071.
"""

import requests
import json
import time
from datetime import datetime

API_URL = "http://localhost:7071/api/chat"
TIMEOUT = 30

def test_route(name, message):
    """Test a specific routing path."""
    print(f"\n{'='*70}")
    print(f"TEST: {name}")
    print(f"{'='*70}")
    print(f"Message: {message}")
    print(f"Time: {datetime.now().isoformat()}")
    
    try:
        start = time.time()
        response = requests.post(
            API_URL,
            json={"message": message},
            timeout=TIMEOUT
        )
        duration = time.time() - start
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ SUCCESS ({response.status_code}) - {duration:.2f}s")
            print(f"Agent: {data.get('agent_used', 'N/A')}")
            print(f"Route: {' → '.join(data.get('trace', {}).get('route_path', []))}")
            print(f"Routing decision: {data.get('trace', {}).get('routing_decision', 'N/A')}")
            print(f"Response preview: {data.get('message', '')[:100]}...")
            return True
        else:
            print(f"❌ FAILED ({response.status_code})")
            print(f"Response: {response.text[:200]}")
            return False
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

def main():
    print("\n" + "="*70)
    print("CHAT ENDPOINT ROUTING VERIFICATION")
    print("="*70)
    
    tests = [
        ("Greeting", "Hello! How are you?"),
        ("Greeting", "Hi, I need help"),
        ("URL - HTTP", "Check this link: https://example.com for me"),
        ("URL - HTTPS", "Is www.example.com safe?"),
        ("Suspicious - Scam keyword", "Hey! You've won a prize! Click here to claim"),
        ("Suspicious - Crypto", "Invest in Bitcoin now!"),
        ("Normal message", "Tell me about scams"),
    ]
    
    results = []
    for name, message in tests:
        success = test_route(name, message)
        results.append((name, success))
        time.sleep(1)  # Rate limit requests
    
    # Summary
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    passed = sum(1 for _, s in results if s)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    for name, success in results:
        status = "✅" if success else "❌"
        print(f"{status} {name}")

if __name__ == "__main__":
    main()
