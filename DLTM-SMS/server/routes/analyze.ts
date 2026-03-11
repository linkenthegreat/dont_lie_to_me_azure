import { Router, Request, Response } from 'express';
import { analyzeMessage } from '../engine/scamDetector.js';

const router = Router();

router.post('/', (req: Request, res: Response) => {
  const { phoneNumber, messageText } = req.body;

  if (!messageText || typeof messageText !== 'string' || messageText.trim() === '') {
    res.status(400).json({ error: 'messageText is required' });
    return;
  }

  const result = analyzeMessage(messageText.trim(), phoneNumber?.trim());
  res.json(result);
});

export default router;
