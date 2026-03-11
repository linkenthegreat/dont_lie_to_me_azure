export interface OnlineSearchResult {
  source: string;
  finding: string;
  riskIndicator: 'positive' | 'neutral' | 'negative';
}

export function simulateOnlineSearch(phoneNumber: string): OnlineSearchResult[] {
  const results: OnlineSearchResult[] = [];
  const cleaned = phoneNumber.replace(/[\s\-()]/g, '');

  // International numbers (non-US)
  if (cleaned.startsWith('+44') || cleaned.startsWith('+91') || cleaned.startsWith('+234') || cleaned.startsWith('+86')) {
    results.push({
      source: 'WhoCalledMe.com',
      finding: `International number flagged by 23 users as potential scam caller`,
      riskIndicator: 'negative',
    });
    results.push({
      source: 'FTC Consumer Database',
      finding: `Multiple complaints filed against numbers from this country code`,
      riskIndicator: 'negative',
    });
    results.push({
      source: 'Reddit r/scams',
      finding: `Similar number reported in scam thread with 150+ upvotes`,
      riskIndicator: 'negative',
    });
    return results;
  }

  // 800/900 toll-free numbers
  if (cleaned.includes('800') || cleaned.includes('888') || cleaned.includes('877') || cleaned.includes('900')) {
    results.push({
      source: 'SpamCalls.net',
      finding: `Toll-free number with 8 spam reports in the last 30 days`,
      riskIndicator: 'negative',
    });
    results.push({
      source: 'Better Business Bureau',
      finding: `Number not registered with any accredited business`,
      riskIndicator: 'neutral',
    });
    return results;
  }

  // Numbers with certain area codes known for scams
  if (cleaned.includes('809') || cleaned.includes('876') || cleaned.includes('284')) {
    results.push({
      source: 'FTC Consumer Database',
      finding: `Area code frequently associated with international callback scams`,
      riskIndicator: 'negative',
    });
    results.push({
      source: 'WhoCalledMe.com',
      finding: `15 users reported unwanted calls from this area code`,
      riskIndicator: 'negative',
    });
    results.push({
      source: 'Reddit r/scams',
      finding: `Caribbean area code commonly used in advance-fee scam operations`,
      riskIndicator: 'negative',
    });
    return results;
  }

  // Short codes (5-6 digits)
  if (cleaned.length <= 6) {
    results.push({
      source: 'CTIA Short Code Registry',
      finding: `Short code not found in the official US short code directory`,
      riskIndicator: 'neutral',
    });
    results.push({
      source: 'SpamCalls.net',
      finding: `No reports found for this short code`,
      riskIndicator: 'neutral',
    });
    return results;
  }

  // Default - unknown US number
  // Use a hash of the phone number to create deterministic but varied results
  const hash = simpleHash(cleaned);

  if (hash % 3 === 0) {
    results.push({
      source: 'WhoCalledMe.com',
      finding: `3 users reported this number as spam/telemarketing`,
      riskIndicator: 'negative',
    });
    results.push({
      source: 'SpamCalls.net',
      finding: `Number flagged as potential robocall source`,
      riskIndicator: 'negative',
    });
    results.push({
      source: 'Better Business Bureau',
      finding: `No business registration found for this number`,
      riskIndicator: 'neutral',
    });
  } else if (hash % 3 === 1) {
    results.push({
      source: 'WhoCalledMe.com',
      finding: `No reports found for this number`,
      riskIndicator: 'neutral',
    });
    results.push({
      source: 'SpamCalls.net',
      finding: `Number appears to be a standard mobile number`,
      riskIndicator: 'neutral',
    });
    results.push({
      source: 'FTC Consumer Database',
      finding: `No complaints on file for this number`,
      riskIndicator: 'positive',
    });
  } else {
    results.push({
      source: 'WhoCalledMe.com',
      finding: `1 user reported receiving suspicious texts from this number`,
      riskIndicator: 'negative',
    });
    results.push({
      source: 'Better Business Bureau',
      finding: `Number not associated with any registered business`,
      riskIndicator: 'neutral',
    });
  }

  return results;
}

function simpleHash(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}
