import { useState } from 'react';
import {
  makeStyles,
  tokens,
  Card,
  Textarea,
  Input,
  Button,
  Spinner,
  ProgressBar,
  Text,
} from '@fluentui/react-components';
import {
  ScanDash24Regular,
  Delete24Regular,
} from '@fluentui/react-icons';
import DemoMessages from './DemoMessages';
import AnalysisResult from './AnalysisResult';
import { analyzeMessage } from '../api/client';

const useStyles = makeStyles({
  card: {
    padding: '24px',
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '16px',
  },
  label: {
    fontWeight: 600,
    fontSize: '14px',
    marginBottom: '2px',
    display: 'block',
  },
  sublabel: {
    fontSize: '12px',
    display: 'block',
    color: tokens.colorNeutralForeground3,
    marginBottom: '4px',
  },
  actions: {
    display: 'flex',
    gap: '8px',
    alignItems: 'center',
  },
  loading: {
    display: 'flex',
    flexDirection: 'column',
    gap: '12px',
    alignItems: 'center',
    padding: '24px',
  },
  charCount: {
    fontSize: '12px',
    color: tokens.colorNeutralForeground3,
    textAlign: 'right',
  },
});

export default function MessageAnalyzer() {
  const styles = useStyles();
  const [message, setMessage] = useState('');
  const [phoneNumber, setPhoneNumber] = useState('');
  const [loading, setLoading] = useState(false);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [result, setResult] = useState<any>(null);

  const handleAnalyze = async () => {
    if (!message.trim()) return;
    setLoading(true);
    setResult(null);

    try {
      // Small delay for demo effect
      await new Promise(r => setTimeout(r, 800));
      const data = await analyzeMessage(message, phoneNumber || undefined);
      setResult(data);
    } catch (err) {
      console.error('Analysis failed:', err);
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setMessage('');
    setPhoneNumber('');
    setResult(null);
  };

  const handleDemoSelect = (msg: string, phone: string) => {
    setMessage(msg);
    setPhoneNumber(phone);
    setResult(null);
  };

  return (
    <div>
      <Card className={styles.card}>
        <div className={styles.form}>
          <div>
            <Text className={styles.label}>Sender's Phone Number</Text>
            <Text className={styles.sublabel}>Enter the phone number the SMS came from (optional)</Text>
            <Input
              placeholder="+1-555-123-4567"
              value={phoneNumber}
              onChange={(_, d) => setPhoneNumber(d.value)}
              style={{ width: '100%' }}
            />
          </div>

          <div>
            <Text className={styles.label}>SMS Message Content</Text>
            <Text className={styles.sublabel}>Paste the suspicious text message you received</Text>
            <Textarea
              placeholder="Paste the SMS message here..."
              value={message}
              onChange={(_, d) => setMessage(d.value)}
              rows={5}
              resize="vertical"
              style={{ width: '100%' }}
            />
            <div className={styles.charCount}>{message.length} characters</div>
          </div>

          <div className={styles.actions}>
            <Button
              appearance="primary"
              size="large"
              icon={<ScanDash24Regular />}
              onClick={handleAnalyze}
              disabled={!message.trim() || loading}
            >
              Analyze Message
            </Button>
            <Button
              appearance="subtle"
              icon={<Delete24Regular />}
              onClick={handleClear}
              disabled={loading}
            >
              Clear
            </Button>
          </div>
        </div>
      </Card>

      <DemoMessages onSelect={handleDemoSelect} />

      {loading && (
        <div className={styles.loading}>
          <Spinner size="medium" label="Analyzing message for scam indicators..." />
          <ProgressBar style={{ width: '100%', maxWidth: '400px' }} />
        </div>
      )}

      {result && (
        <AnalysisResult result={result} phoneNumber={phoneNumber} />
      )}
    </div>
  );
}
