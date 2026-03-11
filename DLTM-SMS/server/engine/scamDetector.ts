import { detectPatterns, PatternMatch } from './patterns.js';
import { calculatePatternScore, normalizeScore, getRecommendation, RiskLevel } from './riskScorer.js';
import { simulateOnlineSearch, OnlineSearchResult } from './onlineSearch.js';
import { getDatabase } from '../database/connection.js';

export interface AnalysisFlag {
  category: string;
  description: string;
  severity: 'info' | 'warning' | 'danger';
  matchedText: string;
}

export interface NumberLookupResult {
  status: 'known_scam' | 'known_legitimate' | 'not_found' | 'suspicious_online';
  details?: {
    label: string;
    category: string;
    reportedCount: number;
    description: string;
    source: string;
  };
  onlineSearchResults?: OnlineSearchResult[];
}

export interface AnalysisResult {
  riskScore: number;
  riskLevel: RiskLevel;
  summary: string;
  flags: AnalysisFlag[];
  numberLookup: NumberLookupResult;
  recommendation: string;
  analyzedAt: string;
}

export function analyzeMessage(messageText: string, phoneNumber?: string): AnalysisResult {
  // Layer 1: Pattern matching
  const patternMatches: PatternMatch[] = detectPatterns(messageText);
  let rawScore = calculatePatternScore(patternMatches);

  // Layer 2: Number lookup
  const numberLookup = lookupNumber(phoneNumber);

  if (numberLookup.status === 'known_scam') {
    rawScore += 0.40;
  } else if (numberLookup.status === 'known_legitimate') {
    rawScore -= 0.30;
  } else if (numberLookup.status === 'suspicious_online') {
    rawScore += 0.10;
  }

  // Layer 3: Online search adjustment
  if (numberLookup.onlineSearchResults) {
    for (const result of numberLookup.onlineSearchResults) {
      if (result.riskIndicator === 'negative') rawScore += 0.05;
      else if (result.riskIndicator === 'positive') rawScore -= 0.05;
    }
  }

  // Layer 4: Normalize
  const { score, level } = normalizeScore(rawScore);

  // Build flags
  const flags: AnalysisFlag[] = patternMatches
    .filter(m => m.pattern.weight > 0) // don't show legitimacy indicators as flags
    .map(m => ({
      category: m.pattern.category,
      description: m.pattern.description,
      severity: m.pattern.severity,
      matchedText: m.matchedText,
    }));

  // Summary
  const summary = generateSummary(level, flags.length, numberLookup.status);

  // Recommendation
  const recommendation = getRecommendation(level);

  const analyzedAt = new Date().toISOString();

  // Log to database
  try {
    const db = getDatabase();
    const stmt = db.prepare(`
      INSERT INTO analysis_log (phone_number, message_text, risk_score, risk_level, flags_found, number_status, analyzed_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(phoneNumber || null, messageText, score, level, JSON.stringify(flags), numberLookup.status, analyzedAt);
  } catch {
    // Don't fail the analysis if logging fails
  }

  return {
    riskScore: score,
    riskLevel: level,
    summary,
    flags,
    numberLookup,
    recommendation,
    analyzedAt,
  };
}

function lookupNumber(phoneNumber?: string): NumberLookupResult {
  if (!phoneNumber || phoneNumber.trim() === '') {
    return { status: 'not_found' };
  }

  const db = getDatabase();
  const stmt = db.prepare('SELECT * FROM known_numbers WHERE phone_number = ?');
  const row = stmt.get(phoneNumber.trim()) as Record<string, unknown> | undefined;

  if (row) {
    const label = row.label as string;
    if (label === 'legitimate') {
      return {
        status: 'known_legitimate',
        details: {
          label: row.label as string,
          category: row.category as string,
          reportedCount: row.reported_count as number,
          description: row.description as string,
          source: row.source as string,
        },
      };
    } else {
      return {
        status: 'known_scam',
        details: {
          label: row.label as string,
          category: row.category as string,
          reportedCount: row.reported_count as number,
          description: row.description as string,
          source: row.source as string,
        },
      };
    }
  }

  // Not in database - simulate online search
  const onlineResults = simulateOnlineSearch(phoneNumber);
  const negativeCount = onlineResults.filter(r => r.riskIndicator === 'negative').length;

  return {
    status: negativeCount >= 2 ? 'suspicious_online' : 'not_found',
    onlineSearchResults: onlineResults,
  };
}

function generateSummary(level: RiskLevel, flagCount: number, numberStatus: string): string {
  const statusText = numberStatus === 'known_scam'
    ? 'This number is in our scam database.'
    : numberStatus === 'known_legitimate'
      ? 'This number is verified as legitimate.'
      : numberStatus === 'suspicious_online'
        ? 'This number has suspicious reports online.'
        : '';

  switch (level) {
    case 'safe':
      return `This message appears safe. ${statusText}`.trim();
    case 'low':
      return `Low risk detected with ${flagCount} minor concern${flagCount !== 1 ? 's' : ''}. ${statusText}`.trim();
    case 'medium':
      return `Medium risk - ${flagCount} warning sign${flagCount !== 1 ? 's' : ''} detected. Exercise caution. ${statusText}`.trim();
    case 'high':
      return `High risk! ${flagCount} red flag${flagCount !== 1 ? 's' : ''} detected. This is likely a scam. ${statusText}`.trim();
    case 'critical':
      return `CRITICAL: ${flagCount} red flag${flagCount !== 1 ? 's' : ''} detected. This is almost certainly a scam! ${statusText}`.trim();
  }
}
