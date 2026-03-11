import {
  makeStyles,
  tokens,
  Card,
  MessageBar,
  MessageBarBody,
  Text,
  Divider,
} from '@fluentui/react-components';
import RiskGauge from './RiskGauge';
import RedFlagList from './RedFlagList';
import NumberLookup from './NumberLookup';

const useStyles = makeStyles({
  container: {
    display: 'flex',
    flexDirection: 'column',
    gap: '20px',
    marginTop: '20px',
    animation: 'fadeSlideIn 0.5s ease-out',
  },
  topSection: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: '20px',
    '@media (max-width: 700px)': {
      gridTemplateColumns: '1fr',
    },
  },
  gaugeCard: {
    padding: '16px',
    display: 'flex',
    justifyContent: 'center',
  },
  recommendation: {
    padding: '16px',
    backgroundColor: tokens.colorNeutralBackground3,
    borderRadius: '8px',
  },
  recTitle: {
    fontWeight: 600,
    fontSize: '14px',
    marginBottom: '8px',
  },
  recText: {
    fontSize: '14px',
    lineHeight: '22px',
  },
});

interface AnalysisResultProps {
  result: {
    riskScore: number;
    riskLevel: string;
    summary: string;
    flags: Array<{
      category: string;
      description: string;
      severity: 'info' | 'warning' | 'danger';
      matchedText: string;
    }>;
    numberLookup: {
      status: string;
      details?: {
        label: string;
        category: string;
        reportedCount: number;
        description: string;
        source: string;
      };
      onlineSearchResults?: Array<{
        source: string;
        finding: string;
        riskIndicator: 'positive' | 'neutral' | 'negative';
      }>;
    };
    recommendation: string;
  };
  phoneNumber?: string;
}

export default function AnalysisResult({ result, phoneNumber }: AnalysisResultProps) {
  const styles = useStyles();

  const intent = result.riskLevel === 'safe' || result.riskLevel === 'low'
    ? 'success' as const
    : result.riskLevel === 'medium'
      ? 'warning' as const
      : 'error' as const;

  return (
    <div className={styles.container}>
      <MessageBar intent={intent}>
        <MessageBarBody>
          <Text weight="semibold">{result.summary}</Text>
        </MessageBarBody>
      </MessageBar>

      <div className={styles.topSection}>
        <Card className={styles.gaugeCard}>
          <RiskGauge score={result.riskScore} level={result.riskLevel} />
        </Card>

        <NumberLookup phoneNumber={phoneNumber} numberLookup={result.numberLookup} />
      </div>

      <RedFlagList flags={result.flags} />

      <Divider />

      <div className={styles.recommendation}>
        <div className={styles.recTitle}>Recommendation</div>
        <Text className={styles.recText}>{result.recommendation}</Text>
      </div>
    </div>
  );
}
