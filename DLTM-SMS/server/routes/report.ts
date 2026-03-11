import { Router, Request, Response } from 'express';
import { getDatabase } from '../database/connection.js';

const router = Router();

router.post('/', (req: Request, res: Response) => {
  const { phoneNumber, category, description } = req.body;

  if (!phoneNumber || typeof phoneNumber !== 'string' || phoneNumber.trim() === '') {
    res.status(400).json({ error: 'phoneNumber is required' });
    return;
  }

  const db = getDatabase();
  const now = new Date().toISOString().split('T')[0];

  // Check if number already exists
  const existing = db.prepare('SELECT * FROM known_numbers WHERE phone_number = ?').get(phoneNumber.trim()) as Record<string, unknown> | undefined;

  if (existing) {
    // Update existing entry
    db.prepare(
      'UPDATE known_numbers SET reported_count = reported_count + 1, last_reported = ?, label = ? WHERE phone_number = ?'
    ).run(now, 'scam', phoneNumber.trim());

    res.json({ message: 'Number report updated', updated: true });
  } else {
    // Insert new entry
    db.prepare(
      'INSERT INTO known_numbers (phone_number, label, category, reported_count, first_reported, last_reported, description, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(phoneNumber.trim(), 'suspected', category || 'unknown', 1, now, now, description || 'Reported by user', 'community');

    res.json({ message: 'Number reported successfully', updated: false });
  }
});

export default router;
