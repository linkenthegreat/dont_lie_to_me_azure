import {
  makeStyles,
  tokens,
  Card,
  Badge,
  Text,
  Divider,
} from '@fluentui/react-components';
import {
  ShieldError24Filled,
  ShieldCheckmark24Filled,
  Search24Regular,
  Globe24Regular,
} from '@fluentui/react-icons';
import OnlineSearchSimulator from './OnlineSearchSimulator';

const useStyles = makeStyles({
  card: {
    padding: '16px',
  },
  heading: {
    fontSize: '16px',
    fontWeight: 600,
    marginBottom: '12px',
  },
  status: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    marginBottom: '12px',
  },
  statusIcon: {
    fontSize: '32px',
    display: 'flex',
  },
  details: {
    display: 'grid',
    gridTemplateColumns: 'auto 1fr',
    gap: '4px 12px',
    fontSize: '13px',
    marginTop: '8px',
  },
  detailLabel: {
    color: tokens.colorNeutralForeground3,
    fontWeight: 500,
  },
  notFound: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    color: tokens.colorNeutralForeground3,
    marginBottom: '8px',
  },
});

interface NumberLookupProps {
  phoneNumber?: string;
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
}

export default function NumberLookup({ phoneNumber, numberLookup }: NumberLookupProps) {
  const styles = useStyles();

  const statusConfig: Record<string, { label: string; color: 'danger' | 'success' | 'warning' | 'informative'; icon: JSX.Element }> = {
    known_scam: { label: 'Known Scam Number', color: 'danger', icon: <ShieldError24Filled style={{ color: '#a4262c' }} /> },
    known_legitimate: { label: 'Verified Legitimate', color: 'success', icon: <ShieldCheckmark24Filled style={{ color: '#0f7b0f' }} /> },
    suspicious_online: { label: 'Suspicious (Online Reports)', color: 'warning', icon: <Globe24Regular style={{ color: '#ca5010' }} /> },
    not_found: { label: 'Not Found in Database', color: 'informative', icon: <Search24Regular /> },
  };

  const config = statusConfig[numberLookup.status] || statusConfig.not_found;

  return (
    <div>
      <Text className={styles.heading}>Number Lookup</Text>
      <Card className={styles.card}>
        <div className={styles.status}>
          <div className={styles.statusIcon}>{config.icon}</div>
          <div>
            <Text weight="semibold">{phoneNumber || 'No number provided'}</Text>
            <br />
            <Badge size="medium" appearance="filled" color={config.color}>{config.label}</Badge>
          </div>
        </div>

        {numberLookup.details && (
          <>
            <Divider />
            <div className={styles.details}>
              <span className={styles.detailLabel}>Category:</span>
              <span>{formatCategory(numberLookup.details.category)}</span>
              <span className={styles.detailLabel}>Reports:</span>
              <span>{numberLookup.details.reportedCount} reports</span>
              <span className={styles.detailLabel}>Description:</span>
              <span>{numberLookup.details.description}</span>
              <span className={styles.detailLabel}>Source:</span>
              <span>{numberLookup.details.source.toUpperCase()}</span>
            </div>
          </>
        )}

        {numberLookup.onlineSearchResults && numberLookup.onlineSearchResults.length > 0 && (
          <>
            <Divider style={{ margin: '12px 0' }} />
            <OnlineSearchSimulator results={numberLookup.onlineSearchResults} />
          </>
        )}
      </Card>
    </div>
  );
}

function formatCategory(cat: string): string {
  return cat.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}
