import express from 'express';
import cors from 'cors';
import { initializeDatabase } from './database/init.js';
import { seedDatabase } from './database/seed.js';
import analyzeRouter from './routes/analyze.js';
import numbersRouter from './routes/numbers.js';
import reportRouter from './routes/report.js';

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());

// Initialize database
initializeDatabase();
seedDatabase();

// Routes
app.use('/api/analyze', analyzeRouter);
app.use('/api/numbers', numbersRouter);
app.use('/api/report', reportRouter);

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
