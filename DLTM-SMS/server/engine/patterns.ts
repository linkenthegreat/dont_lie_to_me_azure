export interface ScamPattern {
  id: string;
  category: string;
  description: string;
  severity: 'info' | 'warning' | 'danger';
  weight: number;
  matchers: RegExp[];
}

export const SCAM_PATTERNS: ScamPattern[] = [
  // URGENCY
  {
    id: 'urgency_immediate',
    category: 'Urgency',
    description: 'Demands immediate action to pressure you into responding without thinking',
    severity: 'warning',
    weight: 0.15,
    matchers: [/\b(immediate(ly)?|right now|right away|asap)\b/i],
  },
  {
    id: 'urgency_deadline',
    category: 'Urgency',
    description: 'Sets a tight deadline to create panic and prevent careful consideration',
    severity: 'warning',
    weight: 0.20,
    matchers: [/\b(within \d+ hours?|expires? (today|tonight|soon)|last chance|final notice)\b/i],
  },
  {
    id: 'urgency_threat',
    category: 'Urgency',
    description: 'Threatens negative consequences like account suspension or arrest',
    severity: 'danger',
    weight: 0.25,
    matchers: [/\b(will be (suspended|locked|closed|deleted|terminated|deactivated)|avoid (arrest|penalty|suspension|charges))\b/i],
  },
  {
    id: 'urgency_act_now',
    category: 'Urgency',
    description: 'Uses high-pressure language to rush you into action',
    severity: 'warning',
    weight: 0.15,
    matchers: [/\b(act now|don'?t delay|urgent|time.sensitive|limited time)\b/i],
  },

  // SUSPICIOUS LINKS
  {
    id: 'link_shortened',
    category: 'Suspicious Link',
    description: 'Contains a shortened URL that hides the real destination',
    severity: 'warning',
    weight: 0.20,
    matchers: [/\b(bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|rb\.gy)\/\w+/i],
  },
  {
    id: 'link_suspicious_tld',
    category: 'Suspicious Link',
    description: 'Link uses a suspicious domain extension commonly used by scammers',
    severity: 'danger',
    weight: 0.30,
    matchers: [/https?:\/\/[^\s]+\.(tk|ml|ga|cf|gq|xyz|top|buzz|info|click|co)\b/i],
  },
  {
    id: 'link_lookalike',
    category: 'Suspicious Link',
    description: 'URL mimics a well-known brand with slight misspellings',
    severity: 'danger',
    weight: 0.35,
    matchers: [/https?:\/\/[^\s]*(paypa1|amaz0n|app1e|chasse|we11s|micr0soft|chase-|appleid-|usps-|ezpass-)[^\s]*/i],
  },
  {
    id: 'link_ip_address',
    category: 'Suspicious Link',
    description: 'URL uses an IP address instead of a domain name - highly suspicious',
    severity: 'danger',
    weight: 0.30,
    matchers: [/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i],
  },
  {
    id: 'link_present',
    category: 'Suspicious Link',
    description: 'Message contains a link - always verify URLs from unknown senders',
    severity: 'info',
    weight: 0.10,
    matchers: [/https?:\/\/[^\s]+/i],
  },

  // FINANCIAL REQUEST
  {
    id: 'financial_send_money',
    category: 'Financial Request',
    description: 'Requests money transfer through untraceable payment methods',
    severity: 'danger',
    weight: 0.25,
    matchers: [/\b(send \$?\d+|wire transfer|zelle|venmo|cash.?app|gift card|money order|bitcoin|crypto)\b/i],
  },
  {
    id: 'financial_fee',
    category: 'Financial Request',
    description: 'Requests a small fee - a common tactic to get payment information',
    severity: 'warning',
    weight: 0.20,
    matchers: [/\b(processing fee|shipping fee|activation fee|handling fee|redelivery fee|customs fee)\b/i],
  },
  {
    id: 'financial_bank_action',
    category: 'Financial Request',
    description: 'Asks you to verify account or payment details through an unofficial channel',
    severity: 'danger',
    weight: 0.25,
    matchers: [/\b(verify your (account|identity|card)|confirm your (payment|details)|update.{0,15}(billing|payment))\b/i],
  },
  {
    id: 'financial_prize',
    category: 'Financial Request',
    description: 'Claims you won a prize - legitimate prizes never require upfront payment',
    severity: 'danger',
    weight: 0.30,
    matchers: [/\b(claim your (prize|reward|winnings)|you('ve| have) won \$?\d+|winner of \$?\d+)\b/i],
  },

  // PERSONAL INFO REQUEST
  {
    id: 'pii_ssn',
    category: 'Personal Info Request',
    description: 'Requests Social Security Number - no legitimate text will ask for this',
    severity: 'danger',
    weight: 0.30,
    matchers: [/\b(social security|ssn|ss#|social security number)\b/i],
  },
  {
    id: 'pii_credentials',
    category: 'Personal Info Request',
    description: 'Asks for login credentials or sensitive financial data',
    severity: 'danger',
    weight: 0.25,
    matchers: [/\b(password|login credentials|username|pin code|security code|cvv|routing number|account number)\b/i],
  },
  {
    id: 'pii_verify_identity',
    category: 'Personal Info Request',
    description: 'Requests identity verification through unofficial channels',
    severity: 'warning',
    weight: 0.20,
    matchers: [/\b(verify your identity|confirm your identity|prove who you are)\b/i],
  },

  // IMPERSONATION
  {
    id: 'impersonation_government',
    category: 'Impersonation',
    description: 'Claims to be from a government agency - real agencies rarely text you',
    severity: 'danger',
    weight: 0.20,
    matchers: [/\b(irs|fbi|dea|ssa|social security administration|department of|federal bureau)\b/i],
  },
  {
    id: 'impersonation_bank',
    category: 'Impersonation',
    description: 'Impersonates a bank or financial institution',
    severity: 'warning',
    weight: 0.15,
    matchers: [/\b(chase (account|bank)|wells fargo|bank of america|citibank|capital one|your bank account)\b/i],
  },
  {
    id: 'impersonation_tech',
    category: 'Impersonation',
    description: 'Impersonates a tech company to steal your credentials',
    severity: 'warning',
    weight: 0.15,
    matchers: [/\b(apple.?id|microsoft account|google.?account|amazon.?account)\b/i],
  },
  {
    id: 'impersonation_delivery',
    category: 'Impersonation',
    description: 'Impersonates a delivery service - verify directly on the official website',
    severity: 'info',
    weight: 0.10,
    matchers: [/\b(usps|fedex|ups|dhl).{0,30}(deliver|package|tracking|shipment)\b/i],
  },

  // SOCIAL ENGINEERING
  {
    id: 'social_generic_greeting',
    category: 'Social Engineering',
    description: 'Uses a generic greeting instead of your name - sign of mass messaging',
    severity: 'info',
    weight: 0.10,
    matchers: [/^(dear (customer|user|friend|sir|madam|valued)|hi there|hello there)/i],
  },
  {
    id: 'social_wrong_number',
    category: 'Social Engineering',
    description: 'Pretends to have the wrong number - a common conversation starter for romance scams',
    severity: 'info',
    weight: 0.05,
    matchers: [/\b(is this .{2,20}\?|wrong (number|person)|gave me this number)\b/i],
  },
  {
    id: 'social_emotional',
    category: 'Social Engineering',
    description: 'Uses emotional manipulation like congratulations or exclusivity to lower your guard',
    severity: 'warning',
    weight: 0.15,
    matchers: [/\b(congratulations|you('ve| have) been (selected|chosen)|exclusive offer|special offer)\b/i],
  },

  // GRAMMAR / FORMATTING
  {
    id: 'grammar_excessive_punctuation',
    category: 'Formatting Red Flag',
    description: 'Uses excessive punctuation - common in scam messages',
    severity: 'info',
    weight: 0.05,
    matchers: [/[!?]{3,}|\.{4,}/],
  },
  {
    id: 'grammar_case_id',
    category: 'Formatting Red Flag',
    description: 'Includes a fake case/reference number to appear official',
    severity: 'info',
    weight: 0.10,
    matchers: [/\b(case|ref|ticket|id)\s?[#:]?\s?[A-Z0-9-]{6,}\b/i],
  },

  // CONTACT REQUEST
  {
    id: 'contact_call_back',
    category: 'Contact Request',
    description: 'Urges you to call a number - scammers use this to steal info over the phone',
    severity: 'warning',
    weight: 0.10,
    matchers: [/\b(call (us|me|back|this number|immediately)|dial \d{3})/i],
  },
  {
    id: 'contact_move_platform',
    category: 'Contact Request',
    description: 'Tries to move conversation to another platform to avoid detection',
    severity: 'warning',
    weight: 0.15,
    matchers: [/\b(whatsapp|telegram|signal|text me at|reach me at|add me on)\b/i],
  },

  // LEGITIMACY INDICATORS (negative weight = reduces risk)
  {
    id: 'legit_opt_out',
    category: 'Legitimacy Indicator',
    description: 'Contains opt-out instructions - sign of a legitimate business message',
    severity: 'info',
    weight: -0.10,
    matchers: [/\b(reply stop|text stop|opt.?out|unsubscribe)\b/i],
  },
];

export interface PatternMatch {
  pattern: ScamPattern;
  matchedText: string;
}

export function detectPatterns(messageText: string): PatternMatch[] {
  const matches: PatternMatch[] = [];

  for (const pattern of SCAM_PATTERNS) {
    for (const matcher of pattern.matchers) {
      const match = messageText.match(matcher);
      if (match) {
        matches.push({
          pattern,
          matchedText: match[0],
        });
        break; // only count each pattern once
      }
    }
  }

  return matches;
}
