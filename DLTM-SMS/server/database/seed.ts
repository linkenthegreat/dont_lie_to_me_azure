import { getDatabase } from './connection.js';

export function seedDatabase(): void {
  const db = getDatabase();

  // Check if already seeded
  const count = (db.prepare('SELECT COUNT(*) as count FROM scam_templates').get() as Record<string, number>).count;
  if (count > 0) {
    console.log('Database already seeded, skipping');
    return;
  }

  const insertNumber = db.prepare(`
    INSERT OR IGNORE INTO known_numbers (phone_number, label, category, reported_count, first_reported, last_reported, description, source)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const scamNumbers = [
    ['+1-809-555-0147', 'scam', 'prize_scam', 89, '2024-06-15', '2026-03-01', 'Jamaican lottery scam operation - claims victims won millions', 'ftc'],
    ['+1-323-555-0199', 'scam', 'bank_fraud', 47, '2025-01-10', '2026-02-28', 'Chase Bank impersonation - sends fake account lock alerts', 'community'],
    ['+1-202-555-0188', 'scam', 'irs_scam', 156, '2024-03-20', '2026-03-05', 'IRS impersonation - threatens arrest for unpaid taxes', 'ftc'],
    ['+1-415-555-0162', 'scam', 'phishing', 63, '2025-04-12', '2026-02-20', 'Apple ID credential harvesting via fake verification links', 'community'],
    ['+1-312-555-0134', 'scam', 'delivery_scam', 38, '2025-07-01', '2026-03-08', 'Fake USPS delivery notifications requesting redelivery fees', 'carrier'],
    ['+1-786-555-0111', 'scam', 'tech_support', 72, '2024-11-05', '2026-02-15', 'Microsoft tech support scam - claims computer is infected', 'community'],
    ['+1-469-555-0178', 'scam', 'bank_fraud', 29, '2025-09-18', '2026-03-02', 'Wells Fargo suspicious activity scam with fake login page', 'community'],
    ['+1-617-555-0156', 'suspected', 'romance', 12, '2025-12-01', '2026-02-10', 'Romance scam starter - pretends wrong number to initiate conversation', 'community'],
    ['+44-20-5555-0123', 'scam', 'phishing', 34, '2025-05-22', '2026-01-30', 'UK HMRC tax refund phishing targeting US numbers', 'ftc'],
    ['+1-800-555-0199', 'scam', 'prize_scam', 201, '2024-01-15', '2026-03-09', 'Fake Amazon gift card giveaway - requests processing fee', 'ftc'],
    ['+1-213-555-0145', 'scam', 'delivery_scam', 55, '2025-06-30', '2026-03-07', 'FedEx customs fee scam - fake international package held', 'carrier'],
    ['+1-571-555-0167', 'suspected', 'phishing', 18, '2025-10-14', '2026-02-25', 'Social security number harvesting via fake government texts', 'community'],
  ];

  const legitimateNumbers = [
    ['+1-800-275-2273', 'legitimate', 'legitimate_business', 0, '2020-01-01', '2026-03-10', 'Apple Support official number', 'verified'],
    ['72727', 'legitimate', 'legitimate_business', 0, '2020-01-01', '2026-03-10', 'T-Mobile official short code for account alerts', 'verified'],
    ['22000', 'legitimate', 'legitimate_business', 0, '2020-01-01', '2026-03-10', 'Target official short code for order updates', 'verified'],
    ['+1-800-922-0204', 'legitimate', 'legitimate_business', 0, '2020-01-01', '2026-03-10', 'Verizon Wireless official customer service', 'verified'],
  ];

  for (const row of [...scamNumbers, ...legitimateNumbers]) {
    insertNumber.run(...row);
  }

  const insertTemplate = db.prepare(`
    INSERT OR IGNORE INTO scam_templates (category, template_name, message_text, sender_number, description)
    VALUES (?, ?, ?, ?, ?)
  `);

  const templates = [
    ['bank_fraud', 'Urgent Bank Alert', 'ALERT: Your Chase account has been locked due to suspicious activity. Verify your identity immediately to avoid permanent suspension: http://chase-secure-verify.tk/login', '+1-323-555-0199', 'Fake Chase bank account lock alert with phishing link'],
    ['irs_scam', 'IRS Threat', 'FINAL NOTICE: The IRS has filed a lawsuit against you for unpaid taxes of $4,832.67. To avoid arrest, call immediately: 202-555-0188. Case #IRS-2026-4481', '+1-202-555-0188', 'Threatening IRS impersonation demanding immediate payment'],
    ['delivery_scam', 'Package Delivery Fee', 'USPS: Your package (tracking #9400128205) could not be delivered. A $3.99 redelivery fee is required. Pay now: http://usps-redelivery.info/pay', '+1-312-555-0134', 'Fake USPS delivery notification requesting small fee payment'],
    ['prize_scam', 'Prize Winner', 'CONGRATULATIONS! You\'ve been selected as the winner of $1,000,000 in the International Sweepstakes! To claim your prize, send $50 processing fee via Zelle to claim@prizes.com', '+1-809-555-0147', 'Classic lottery/sweepstakes scam requiring upfront fee'],
    ['phishing', 'Apple ID Disabled', 'Your Apple ID has been disabled for security reasons. You must verify your account within 24 hours or it will be permanently deleted. Verify here: http://appleid-verify.support/restore', '+1-415-555-0162', 'Apple ID phishing with fake verification link and urgency'],
    ['romance', 'Wrong Number Starter', 'Hey, is this Sarah? My friend gave me this number. Sorry if wrong person! I\'m looking for my friend from yoga class. Anyway, I\'m Jessica, nice to meet you lol', '+1-617-555-0156', 'Romance scam opener using wrong number pretense'],
    ['phishing', 'Toll Payment Due', 'Outstanding toll balance of $6.99 on your E-ZPass. Pay within 24hrs to avoid $50 late penalty. Pay now: http://ezpass-payment.co/balance', '+1-571-555-0167', 'Fake toll payment scam with urgency and small amount'],
    ['legitimate_business', 'T-Mobile Bill Reminder', 'T-Mobile: Your bill of $85.00 is due on 03/15. Pay at t-mobile.com or dial 611 from your T-Mobile phone. Reply STOP to opt out.', '72727', 'Legitimate carrier billing notification for comparison'],
  ];

  for (const row of templates) {
    insertTemplate.run(...row);
  }

  console.log('Database seeded with sample data');
}
