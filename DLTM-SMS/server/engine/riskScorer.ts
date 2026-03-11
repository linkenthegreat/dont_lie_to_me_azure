import { PatternMatch } from './patterns.js';

export type RiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical';

export interface RiskResult {
  score: number;
  level: RiskLevel;
}

export function calculatePatternScore(matches: PatternMatch[]): number {
  let score = 0;
  for (const match of matches) {
    score += match.pattern.weight;
  }
  return score;
}

export function normalizeScore(rawScore: number): RiskResult {
  const score = Math.max(0, Math.min(1, rawScore));

  let level: RiskLevel;
  if (score < 0.15) level = 'safe';
  else if (score < 0.35) level = 'low';
  else if (score < 0.55) level = 'medium';
  else if (score < 0.75) level = 'high';
  else level = 'critical';

  return { score: Math.round(score * 100) / 100, level };
}

export function getRecommendation(level: RiskLevel): string {
  switch (level) {
    case 'safe':
      return 'This message appears to be from a legitimate source. No significant red flags detected.';
    case 'low':
      return 'This message has minor concerns. Verify the sender if you don\'t recognize the number before taking any action.';
    case 'medium':
      return 'This message shows several warning signs. Do NOT click any links. Verify the sender through official channels (call the company directly using a number from their official website).';
    case 'high':
      return 'This message is very likely a scam. Do NOT respond, do NOT click any links, and do NOT share any personal information. Block the number.';
    case 'critical':
      return 'This is almost certainly a scam. Block this number immediately, report it to your carrier by forwarding the message to 7726 (SPAM), and report to the FTC at reportfraud.ftc.gov.';
  }
}
