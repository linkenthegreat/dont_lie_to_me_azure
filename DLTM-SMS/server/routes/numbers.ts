import { Router, Request, Response } from 'express';
import { getDatabase } from '../database/connection.js';

const router = Router();

// GET /api/numbers - List known numbers
router.get('/', (req: Request, res: Response) => {
  const db = getDatabase();
  const { label, category } = req.query;

  let sql = 'SELECT * FROM known_numbers';
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (label && typeof label === 'string') {
    conditions.push('label = ?');
    params.push(label);
  }
  if (category && typeof category === 'string') {
    conditions.push('category = ?');
    params.push(category);
  }

  if (conditions.length > 0) {
    sql += ' WHERE ' + conditions.join(' AND ');
  }

  sql += ' ORDER BY reported_count DESC';

  const stmt = db.prepare(sql);
  const rows = stmt.all(...params);
  res.json({ numbers: rows, total: rows.length });
});

// GET /api/templates - Demo message templates
router.get('/templates', (_req: Request, res: Response) => {
  const db = getDatabase();
  const stmt = db.prepare('SELECT * FROM scam_templates ORDER BY id');
  const rows = stmt.all();
  res.json({ templates: rows });
});

// GET /api/stats - Dashboard statistics
router.get('/stats', (_req: Request, res: Response) => {
  const db = getDatabase();

  const totalScam = (db.prepare('SELECT COUNT(*) as count FROM known_numbers WHERE label IN (?, ?)').get('scam', 'suspected') as Record<string, number>).count;
  const totalLegit = (db.prepare('SELECT COUNT(*) as count FROM known_numbers WHERE label = ?').get('legitimate') as Record<string, number>).count;
  const totalAnalyses = (db.prepare('SELECT COUNT(*) as count FROM analysis_log').get() as Record<string, number>).count;

  const categories = db.prepare(
    'SELECT category, COUNT(*) as count FROM known_numbers WHERE label IN (?, ?) GROUP BY category ORDER BY count DESC'
  ).all('scam', 'suspected') as Array<{ category: string; count: number }>;

  res.json({
    totalScamNumbers: totalScam,
    totalLegitimateNumbers: totalLegit,
    totalAnalyses,
    topCategories: categories,
  });
});

export default router;
