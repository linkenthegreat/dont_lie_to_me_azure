Cosmos DB — Practical Summary & Project Notes

1. What Cosmos DB Actually Is
Cosmos DB is a globally distributed, multi‑model NoSQL database designed for:
• 	Low latency
• 	High availability
• 	Horizontal scalability
• 	Flexible schema
It supports multiple data models:
• 	Document (Core SQL API)
• 	Key‑value
• 	Column‑family
• 	Graph (Gremlin)
• 	MongoDB API
For most modern apps, the Core (SQL) API is the default and easiest to use.

2. Key Concepts (The Parts That Matter Most)
Document Model
Data is stored as JSON documents, not tables.
This gives flexibility — you can evolve your schema without migrations.
Partition Key
The most important design decision.
It determines:
• 	Scalability
• 	Performance
• 	Cost
Good partition keys:
• 	Have high cardinality
• 	Distribute load evenly
• 	Are used frequently in queries
Examples: , , , .
Request Units (RUs)
Cosmos DB charges based on RUs, not storage.
Every read/write/query consumes RUs.
Good data modeling reduces RU cost.
Consistency Levels
Cosmos offers 5 levels:
• 	Strong
• 	Bounded staleness
• 	Session (default, best balance)
• 	Consistent prefix
• 	Eventual
For most apps, Session is ideal.
Global Distribution
You can replicate data across regions with a click.
Useful for:
• 	Low latency
• 	Disaster recovery
• 	Multi‑region apps

3. Why Cosmos DB Fits Our Project
Our anti‑scam project likely needs:
• 	Fast reads/writes
• 	Flexible document structure
• 	Ability to store different types of data (users, scam reports, crypto addresses, logs)
• 	Potential global access
• 	Real‑time updates
Cosmos DB supports all of these naturally.
Examples of data we may store:
• 	User profiles
• 	Scam reports
• 	Crypto address reputation
• 	Message analysis results
• 	Logs or audit trails

4. Suggested Data Models (Draft)
User Document
{
  "id": "user123",
  "email": "test@example.com",
  "createdAt": "2026-03-01",
  "riskScore": 0.2,
  "partitionKey": "user123"
}

Scam Report Document
{
  "id": "report789",
  "userId": "user123",
  "type": "crypto",
  "address": "0x123...",
  "analysis": {
    "riskLevel": "high",
    "reason": "Known scam address"
  },
  "timestamp": "2026-03-02",
  "partitionKey": "user123"
}

Crypto Address Reputation Document
{
  "address": "0x123...",
  "riskLevel": "high",
  "sources": ["Etherscan", "Chainabuse"],
  "lastUpdated": "2026-03-02",
  "partitionKey": "0x123..."
}

5. Recommended Partition Key Strategy
Option A — Partition by userId
Good for:
- User‑centric data
- Scam reports tied to users
Option B — Partition by address
Good for:
- Crypto address reputation
- Fast lookups
We can mix strategies by using multiple containers, each with its own partition key.

6. Development Setup (Free)
Cosmos DB Emulator
- Runs locally
- No Azure cost
- Perfect for development
- Supports Core SQL API

