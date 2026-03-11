import {
  makeStyles,
  tokens,
  Card,
  Text,
  Divider,
  Badge,
} from '@fluentui/react-components';
import {
  ShieldCheckmark24Regular,
  Database24Regular,
  BrainCircuit24Regular,
  Globe24Regular,
  Phone24Regular,
  Warning24Regular,
} from '@fluentui/react-icons';

const useStyles = makeStyles({
  container: {
    display: 'flex',
    flexDirection: 'column',
    gap: '20px',
  },
  hero: {
    padding: '32px',
    textAlign: 'center',
    backgroundColor: tokens.colorBrandBackground2,
    borderRadius: '12px',
  },
  heroTitle: {
    fontSize: '24px',
    fontWeight: 700,
    marginBottom: '8px',
  },
  heroSub: {
    fontSize: '15px',
    color: tokens.colorNeutralForeground2,
    maxWidth: '600px',
    margin: '0 auto',
    lineHeight: '24px',
  },
  section: {
    padding: '20px',
  },
  sectionTitle: {
    fontSize: '18px',
    fontWeight: 600,
    marginBottom: '16px',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  steps: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '16px',
  },
  step: {
    padding: '20px',
    textAlign: 'center',
  },
  stepIcon: {
    fontSize: '32px',
    color: tokens.colorBrandForeground1,
    marginBottom: '12px',
    display: 'flex',
    justifyContent: 'center',
  },
  stepTitle: {
    fontWeight: 600,
    fontSize: '14px',
    marginBottom: '4px',
  },
  stepDesc: {
    fontSize: '13px',
    color: tokens.colorNeutralForeground3,
    lineHeight: '20px',
  },
  techStack: {
    display: 'flex',
    gap: '8px',
    flexWrap: 'wrap',
    justifyContent: 'center',
    marginTop: '12px',
  },
  tips: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  tip: {
    display: 'flex',
    gap: '8px',
    alignItems: 'flex-start',
    padding: '8px 0',
  },
  tipIcon: {
    color: tokens.colorBrandForeground1,
    flexShrink: 0,
    marginTop: '2px',
  },
  footer: {
    textAlign: 'center',
    padding: '16px',
    color: tokens.colorNeutralForeground3,
    fontSize: '13px',
  },
});

export default function AboutPage() {
  const styles = useStyles();

  return (
    <div className={styles.container}>
      <div className={styles.hero}>
        <div className={styles.heroTitle}>How Don't Lie To Me Works</div>
        <div className={styles.heroSub}>
          Our AI-powered system analyzes SMS messages for scam indicators using pattern recognition,
          a community-driven scammer database, and simulated online search capabilities.
        </div>
      </div>

      <Card className={styles.section}>
        <Text className={styles.sectionTitle}>
          <BrainCircuit24Regular />
          Detection Pipeline
        </Text>
        <div className={styles.steps}>
          <Card className={styles.step}>
            <div className={styles.stepIcon}><Phone24Regular /></div>
            <div className={styles.stepTitle}>1. Input Message</div>
            <div className={styles.stepDesc}>Paste the suspicious SMS message and optionally enter the sender's phone number</div>
          </Card>
          <Card className={styles.step}>
            <div className={styles.stepIcon}><BrainCircuit24Regular /></div>
            <div className={styles.stepTitle}>2. AI Analysis</div>
            <div className={styles.stepDesc}>30+ pattern checks across 8 categories detect urgency, phishing links, impersonation, and more</div>
          </Card>
          <Card className={styles.step}>
            <div className={styles.stepIcon}><Database24Regular /></div>
            <div className={styles.stepTitle}>3. Database Lookup</div>
            <div className={styles.stepDesc}>Phone number is checked against our database of known scam and legitimate numbers</div>
          </Card>
          <Card className={styles.step}>
            <div className={styles.stepIcon}><Globe24Regular /></div>
            <div className={styles.stepTitle}>4. Online Search</div>
            <div className={styles.stepDesc}>If not in database, online sources are searched for reports about the number</div>
          </Card>
          <Card className={styles.step}>
            <div className={styles.stepIcon}><ShieldCheckmark24Regular /></div>
            <div className={styles.stepTitle}>5. Risk Assessment</div>
            <div className={styles.stepDesc}>All signals are combined into a risk score with actionable recommendations</div>
          </Card>
        </div>
      </Card>

      <Card className={styles.section}>
        <Text className={styles.sectionTitle}>
          <Warning24Regular />
          Tips to Stay Safe from SMS Scams
        </Text>
        <div className={styles.tips}>
          <div className={styles.tip}>
            <ShieldCheckmark24Regular className={styles.tipIcon} />
            <Text>Never click links in unexpected text messages. Go directly to the company's official website instead.</Text>
          </div>
          <div className={styles.tip}>
            <ShieldCheckmark24Regular className={styles.tipIcon} />
            <Text>Legitimate companies won't ask for passwords, SSN, or payment via text message.</Text>
          </div>
          <div className={styles.tip}>
            <ShieldCheckmark24Regular className={styles.tipIcon} />
            <Text>Be suspicious of urgency. Scammers create panic to prevent you from thinking clearly.</Text>
          </div>
          <div className={styles.tip}>
            <ShieldCheckmark24Regular className={styles.tipIcon} />
            <Text>Forward spam texts to 7726 (SPAM) to report them to your carrier.</Text>
          </div>
          <div className={styles.tip}>
            <ShieldCheckmark24Regular className={styles.tipIcon} />
            <Text>Report scams to the FTC at reportfraud.ftc.gov to help protect others.</Text>
          </div>
        </div>
      </Card>

      <Card className={styles.section}>
        <Text className={styles.sectionTitle}>Technology Stack</Text>
        <div className={styles.techStack}>
          <Badge size="large" appearance="outline">React</Badge>
          <Badge size="large" appearance="outline">TypeScript</Badge>
          <Badge size="large" appearance="outline">Microsoft Fluent UI</Badge>
          <Badge size="large" appearance="outline">Node.js</Badge>
          <Badge size="large" appearance="outline">Express</Badge>
          <Badge size="large" appearance="outline">SQLite</Badge>
          <Badge size="large" appearance="outline">Azure Ecosystem</Badge>
        </div>
      </Card>

      <Divider />

      <div className={styles.footer}>
        Built for Microsoft Hackathon 2026 | Don't Lie To Me - Protecting Users from SMS Scams
      </div>
    </div>
  );
}
