import {
  makeStyles,
  tokens,
  Card,
  Badge,
  Text,
} from '@fluentui/react-components';
import {
  Warning24Filled,
  ErrorCircle24Filled,
  Info24Filled,
} from '@fluentui/react-icons';

const useStyles = makeStyles({
  container: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  heading: {
    fontSize: '16px',
    fontWeight: 600,
    marginBottom: '4px',
  },
  flag: {
    padding: '12px 16px',
    display: 'flex',
    gap: '12px',
    alignItems: 'flex-start',
  },
  icon: {
    flexShrink: 0,
    marginTop: '2px',
  },
  flagContent: {
    display: 'flex',
    flexDirection: 'column',
    gap: '4px',
    flex: 1,
  },
  flagHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  matchedText: {
    backgroundColor: tokens.colorNeutralBackground4,
    padding: '2px 8px',
    borderRadius: '4px',
    fontSize: '12px',
    fontFamily: 'monospace',
    color: tokens.colorNeutralForeground2,
    display: 'inline-block',
    marginTop: '2px',
  },
  noFlags: {
    padding: '16px',
    textAlign: 'center',
    color: tokens.colorNeutralForeground3,
  },
});

interface Flag {
  category: string;
  description: string;
  severity: 'info' | 'warning' | 'danger';
  matchedText: string;
}

interface RedFlagListProps {
  flags: Flag[];
}

export default function RedFlagList({ flags }: RedFlagListProps) {
  const styles = useStyles();

  if (flags.length === 0) {
    return (
      <div>
        <Text className={styles.heading}>Red Flags Found</Text>
        <Card className={styles.noFlags}>
          <Text>No red flags detected in this message.</Text>
        </Card>
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <Text className={styles.heading}>Red Flags Found ({flags.length})</Text>
      {flags.map((flag, i) => (
        <Card key={i} className={styles.flag}>
          <div className={styles.icon}>
            {flag.severity === 'danger' && <ErrorCircle24Filled style={{ color: '#a4262c' }} />}
            {flag.severity === 'warning' && <Warning24Filled style={{ color: '#ca5010' }} />}
            {flag.severity === 'info' && <Info24Filled style={{ color: '#0078d4' }} />}
          </div>
          <div className={styles.flagContent}>
            <div className={styles.flagHeader}>
              <Badge
                size="small"
                appearance="filled"
                color={flag.severity === 'danger' ? 'danger' : flag.severity === 'warning' ? 'warning' : 'informative'}
              >
                {flag.category}
              </Badge>
            </div>
            <Text size={300}>{flag.description}</Text>
            <code className={styles.matchedText}>Matched: "{flag.matchedText}"</code>
          </div>
        </Card>
      ))}
    </div>
  );
}
