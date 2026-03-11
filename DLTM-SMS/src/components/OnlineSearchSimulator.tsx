import { useState, useEffect } from 'react';
import {
  makeStyles,
  tokens,
  Text,
  Spinner,
} from '@fluentui/react-components';

const useStyles = makeStyles({
  container: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  heading: {
    fontSize: '13px',
    fontWeight: 600,
    color: tokens.colorNeutralForeground2,
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  result: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '8px',
    padding: '8px 12px',
    backgroundColor: tokens.colorNeutralBackground3,
    borderRadius: '6px',
    opacity: 0,
    transform: 'translateY(8px)',
    transition: 'opacity 0.4s ease, transform 0.4s ease',
  },
  resultVisible: {
    opacity: 1,
    transform: 'translateY(0)',
  },
  dot: {
    width: '8px',
    height: '8px',
    borderRadius: '50%',
    marginTop: '6px',
    flexShrink: 0,
  },
  source: {
    fontWeight: 600,
    fontSize: '12px',
    color: tokens.colorNeutralForeground2,
  },
  finding: {
    fontSize: '13px',
  },
});

interface SearchResult {
  source: string;
  finding: string;
  riskIndicator: 'positive' | 'neutral' | 'negative';
}

interface OnlineSearchSimulatorProps {
  results: SearchResult[];
}

export default function OnlineSearchSimulator({ results }: OnlineSearchSimulatorProps) {
  const styles = useStyles();
  const [visibleCount, setVisibleCount] = useState(0);
  const [searching, setSearching] = useState(true);

  useEffect(() => {
    setVisibleCount(0);
    setSearching(true);

    const timers: ReturnType<typeof setTimeout>[] = [];

    results.forEach((_, i) => {
      timers.push(setTimeout(() => {
        setVisibleCount(i + 1);
        if (i === results.length - 1) {
          setSearching(false);
        }
      }, 600 * (i + 1)));
    });

    return () => timers.forEach(clearTimeout);
  }, [results]);

  const dotColors: Record<string, string> = {
    positive: '#0f7b0f',
    neutral: '#8a8886',
    negative: '#a4262c',
  };

  return (
    <div className={styles.container}>
      <div className={styles.heading}>
        {searching && <Spinner size="tiny" />}
        <span>{searching ? 'Searching online databases...' : 'Online search complete'}</span>
      </div>

      {results.map((result, i) => (
        <div
          key={i}
          className={styles.result}
          style={i < visibleCount ? { opacity: 1, transform: 'translateY(0)' } : undefined}
        >
          <div
            className={styles.dot}
            style={{ backgroundColor: dotColors[result.riskIndicator] }}
          />
          <div>
            <div className={styles.source}>{result.source}</div>
            <Text className={styles.finding}>{result.finding}</Text>
          </div>
        </div>
      ))}
    </div>
  );
}
