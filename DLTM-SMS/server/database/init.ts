import { getDatabase } from './connection.js';

export function initializeDatabase(): void {
  const db = getDatabase();

  db.exec(`
    CREATE TABLE IF NOT EXISTS known_numbers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phone_number TEXT NOT NULL UNIQUE,
      label TEXT NOT NULL CHECK(label IN ('scam', 'legitimate', 'suspected')),
      category TEXT,
      reported_count INTEGER DEFAULT 1,
      first_reported TEXT NOT NULL,
      last_reported TEXT NOT NULL,
      description TEXT,
      source TEXT DEFAULT 'community'
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS analysis_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phone_number TEXT,
      message_text TEXT NOT NULL,
      risk_score REAL NOT NULL,
      risk_level TEXT NOT NULL,
      flags_found TEXT NOT NULL,
      number_status TEXT,
      analyzed_at TEXT NOT NULL
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS scam_templates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      category TEXT NOT NULL,
      template_name TEXT NOT NULL,
      message_text TEXT NOT NULL,
      sender_number TEXT NOT NULL,
      description TEXT NOT NULL
    )
  `);

  console.log('Database initialized successfully');
}
