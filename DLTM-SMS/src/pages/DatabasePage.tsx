import { useState, useEffect } from 'react';
import {
  makeStyles,
  tokens,
  Card,
  Text,
  Badge,
  Button,
  Input,
  Textarea,
  Dialog,
  DialogTrigger,
  DialogSurface,
  DialogBody,
  DialogTitle,
  DialogContent,
  DialogActions,
  Select,
  Divider,
} from '@fluentui/react-components';
import {
  Add24Regular,
  ArrowSync24Regular,
} from '@fluentui/react-icons';
import { getNumbers, getStats, reportNumber } from '../api/client';

const useStyles = makeStyles({
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '16px',
  },
  statsRow: {
    display: 'flex',
    gap: '12px',
    marginBottom: '20px',
    flexWrap: 'wrap',
  },
  statCard: {
    padding: '16px 20px',
    flex: '1 1 150px',
    textAlign: 'center',
  },
  statNumber: {
    fontSize: '28px',
    fontWeight: 700,
    color: tokens.colorBrandForeground1,
  },
  statLabel: {
    fontSize: '12px',
    color: tokens.colorNeutralForeground3,
    marginTop: '4px',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
  },
  th: {
    textAlign: 'left',
    padding: '10px 12px',
    borderBottom: `2px solid ${tokens.colorNeutralStroke1}`,
    fontSize: '13px',
    fontWeight: 600,
    color: tokens.colorNeutralForeground2,
  },
  td: {
    padding: '10px 12px',
    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
    fontSize: '13px',
  },
  row: {
    ':hover': {
      backgroundColor: tokens.colorNeutralBackground1Hover,
    },
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '12px',
  },
});

interface KnownNumber {
  id: number;
  phone_number: string;
  label: string;
  category: string;
  reported_count: number;
  first_reported: string;
  last_reported: string;
  description: string;
  source: string;
}

interface Stats {
  totalScamNumbers: number;
  totalLegitimateNumbers: number;
  totalAnalyses: number;
  topCategories: Array<{ category: string; count: number }>;
}

export default function DatabasePage() {
  const styles = useStyles();
  const [numbers, setNumbers] = useState<KnownNumber[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [reportPhone, setReportPhone] = useState('');
  const [reportCategory, setReportCategory] = useState('phishing');
  const [reportDesc, setReportDesc] = useState('');

  const loadData = () => {
    getNumbers().then(d => setNumbers(d.numbers)).catch(() => {});
    getStats().then(d => setStats(d)).catch(() => {});
  };

  useEffect(loadData, []);

  const handleReport = async () => {
    if (!reportPhone.trim()) return;
    await reportNumber(reportPhone, reportCategory, reportDesc);
    setDialogOpen(false);
    setReportPhone('');
    setReportDesc('');
    loadData();
  };

  const labelBadge = (label: string) => {
    if (label === 'scam') return <Badge color="danger">Scam</Badge>;
    if (label === 'suspected') return <Badge color="warning">Suspected</Badge>;
    return <Badge color="success">Legitimate</Badge>;
  };

  return (
    <div>
      <div className={styles.header}>
        <Text size={500} weight="semibold">Scammer Database</Text>
        <div style={{ display: 'flex', gap: '8px' }}>
          <Button icon={<ArrowSync24Regular />} onClick={loadData}>Refresh</Button>
          <Dialog open={dialogOpen} onOpenChange={(_, d) => setDialogOpen(d.open)}>
            <DialogTrigger disableButtonEnhancement>
              <Button appearance="primary" icon={<Add24Regular />}>Report Number</Button>
            </DialogTrigger>
            <DialogSurface>
              <DialogBody>
                <DialogTitle>Report a Scam Number</DialogTitle>
                <DialogContent>
                  <div className={styles.form}>
                    <div>
                      <Text weight="semibold" size={300}>Phone Number *</Text>
                      <Input
                        placeholder="+1-555-123-4567"
                        value={reportPhone}
                        onChange={(_, d) => setReportPhone(d.value)}
                        style={{ width: '100%' }}
                      />
                    </div>
                    <div>
                      <Text weight="semibold" size={300}>Category</Text>
                      <Select value={reportCategory} onChange={(_, d) => setReportCategory(d.value)}>
                        <option value="phishing">Phishing</option>
                        <option value="bank_fraud">Bank Fraud</option>
                        <option value="delivery_scam">Delivery Scam</option>
                        <option value="irs_scam">IRS Scam</option>
                        <option value="prize_scam">Prize Scam</option>
                        <option value="tech_support">Tech Support Scam</option>
                        <option value="romance">Romance Scam</option>
                        <option value="other">Other</option>
                      </Select>
                    </div>
                    <div>
                      <Text weight="semibold" size={300}>Description</Text>
                      <Textarea
                        placeholder="Describe what happened..."
                        value={reportDesc}
                        onChange={(_, d) => setReportDesc(d.value)}
                        rows={3}
                        style={{ width: '100%' }}
                      />
                    </div>
                  </div>
                </DialogContent>
                <DialogActions>
                  <DialogTrigger disableButtonEnhancement>
                    <Button>Cancel</Button>
                  </DialogTrigger>
                  <Button appearance="primary" onClick={handleReport} disabled={!reportPhone.trim()}>
                    Submit Report
                  </Button>
                </DialogActions>
              </DialogBody>
            </DialogSurface>
          </Dialog>
        </div>
      </div>

      {stats && (
        <div className={styles.statsRow}>
          <Card className={styles.statCard}>
            <div className={styles.statNumber}>{stats.totalScamNumbers}</div>
            <div className={styles.statLabel}>Scam Numbers</div>
          </Card>
          <Card className={styles.statCard}>
            <div className={styles.statNumber}>{stats.totalLegitimateNumbers}</div>
            <div className={styles.statLabel}>Verified Legitimate</div>
          </Card>
          <Card className={styles.statCard}>
            <div className={styles.statNumber}>{stats.totalAnalyses}</div>
            <div className={styles.statLabel}>Total Analyses</div>
          </Card>
          <Card className={styles.statCard}>
            <div className={styles.statNumber}>{stats.topCategories.length}</div>
            <div className={styles.statLabel}>Scam Categories</div>
          </Card>
        </div>
      )}

      <Divider style={{ marginBottom: '16px' }} />

      <Card style={{ padding: '0', overflow: 'auto' }}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th className={styles.th}>Phone Number</th>
              <th className={styles.th}>Status</th>
              <th className={styles.th}>Category</th>
              <th className={styles.th}>Reports</th>
              <th className={styles.th}>Description</th>
              <th className={styles.th}>Source</th>
            </tr>
          </thead>
          <tbody>
            {numbers.map(n => (
              <tr key={n.id} className={styles.row}>
                <td className={styles.td}><code>{n.phone_number}</code></td>
                <td className={styles.td}>{labelBadge(n.label)}</td>
                <td className={styles.td}>{n.category?.replace(/_/g, ' ')}</td>
                <td className={styles.td}>{n.reported_count}</td>
                <td className={styles.td} style={{ maxWidth: '300px' }}>{n.description}</td>
                <td className={styles.td}><Badge size="small">{n.source}</Badge></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
