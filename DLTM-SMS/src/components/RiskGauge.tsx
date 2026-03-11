import { makeStyles, tokens, Badge } from '@fluentui/react-components';

const useStyles = makeStyles({
  container: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    padding: '16px',
  },
  svg: {
    width: '200px',
    height: '120px',
  },
  scoreText: {
    fontSize: '36px',
    fontWeight: 700,
    marginTop: '-20px',
  },
  label: {
    marginTop: '8px',
  },
});

interface RiskGaugeProps {
  score: number; // 0 to 1
  level: string;
}

export default function RiskGauge({ score, level }: RiskGaugeProps) {
  const styles = useStyles();
  const percentage = Math.round(score * 100);

  // SVG arc parameters
  const cx = 100, cy = 100, r = 80;
  const startAngle = Math.PI;
  const endAngle = 0;
  const scoreAngle = Math.PI - (score * Math.PI);

  const bgArcEnd = polarToCartesian(cx, cy, r, endAngle);
  const bgArcStart = polarToCartesian(cx, cy, r, startAngle);
  const bgPath = `M ${bgArcStart.x} ${bgArcStart.y} A ${r} ${r} 0 0 1 ${bgArcEnd.x} ${bgArcEnd.y}`;

  const scoreArcEnd = polarToCartesian(cx, cy, r, scoreAngle);
  const scorePath = score > 0
    ? `M ${bgArcStart.x} ${bgArcStart.y} A ${r} ${r} 0 ${score > 0.5 ? 1 : 0} 1 ${scoreArcEnd.x} ${scoreArcEnd.y}`
    : '';

  const color = getColor(score);
  const badgeColor = getBadgeColor(level);

  return (
    <div className={styles.container}>
      <svg className={styles.svg} viewBox="0 10 200 100">
        <path d={bgPath} fill="none" stroke={tokens.colorNeutralStroke2} strokeWidth="16" strokeLinecap="round" />
        {scorePath && (
          <path
            d={scorePath}
            fill="none"
            stroke={color}
            strokeWidth="16"
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 1s ease-out' }}
          />
        )}
      </svg>
      <div className={styles.scoreText} style={{ color }}>{percentage}%</div>
      <div className={styles.label}>
        <Badge size="large" appearance="filled" color={badgeColor}>{level.toUpperCase()}</Badge>
      </div>
    </div>
  );
}

function polarToCartesian(cx: number, cy: number, r: number, angle: number) {
  return {
    x: cx + r * Math.cos(angle),
    y: cy - r * Math.sin(angle),
  };
}

function getColor(score: number): string {
  if (score < 0.15) return '#0f7b0f';
  if (score < 0.35) return '#498205';
  if (score < 0.55) return '#ca5010';
  if (score < 0.75) return '#da3b01';
  return '#a4262c';
}

function getBadgeColor(level: string): 'success' | 'warning' | 'danger' | 'informative' {
  switch (level) {
    case 'safe': return 'success';
    case 'low': return 'success';
    case 'medium': return 'warning';
    case 'high': return 'danger';
    case 'critical': return 'danger';
    default: return 'informative';
  }
}
