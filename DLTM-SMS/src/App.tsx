import { useState } from 'react';
import {
  makeStyles,
  tokens,
  TabList,
  Tab,
  SelectTabEvent,
  SelectTabData,
} from '@fluentui/react-components';
import {
  ShieldCheckmark24Regular,
  ScanDash24Regular,
  Database24Regular,
  Info24Regular,
} from '@fluentui/react-icons';
import AnalyzePage from './pages/AnalyzePage';
import DatabasePage from './pages/DatabasePage';
import AboutPage from './pages/AboutPage';

const useStyles = makeStyles({
  root: {
    minHeight: '100vh',
    backgroundColor: tokens.colorNeutralBackground2,
  },
  header: {
    backgroundColor: tokens.colorBrandBackground,
    color: tokens.colorNeutralForegroundOnBrand,
    padding: '16px 24px',
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    boxShadow: tokens.shadow4,
  },
  headerIcon: {
    fontSize: '32px',
    display: 'flex',
  },
  headerText: {
    display: 'flex',
    flexDirection: 'column',
  },
  title: {
    fontSize: '22px',
    fontWeight: 700,
    lineHeight: '28px',
  },
  subtitle: {
    fontSize: '13px',
    opacity: 0.9,
  },
  badge: {
    marginLeft: 'auto',
    fontSize: '11px',
    backgroundColor: 'rgba(255,255,255,0.15)',
    padding: '4px 12px',
    borderRadius: '12px',
  },
  nav: {
    backgroundColor: tokens.colorNeutralBackground1,
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    padding: '0 24px',
  },
  content: {
    maxWidth: '960px',
    margin: '0 auto',
    padding: '24px',
  },
});

type TabValue = 'analyze' | 'database' | 'about';

export default function App() {
  const styles = useStyles();
  const [tab, setTab] = useState<TabValue>('analyze');

  const onTabSelect = (_: SelectTabEvent, data: SelectTabData) => {
    setTab(data.value as TabValue);
  };

  return (
    <div className={styles.root}>
      <div className={styles.header}>
        <div className={styles.headerIcon}>
          <ShieldCheckmark24Regular />
        </div>
        <div className={styles.headerText}>
          <div className={styles.title}>Don't Lie To Me</div>
          <div className={styles.subtitle}>AI-Powered SMS Scam Detection</div>
        </div>
        <div className={styles.badge}>Microsoft Hackathon 2026</div>
      </div>

      <div className={styles.nav}>
        <TabList selectedValue={tab} onTabSelect={onTabSelect}>
          <Tab value="analyze" icon={<ScanDash24Regular />}>Analyze Message</Tab>
          <Tab value="database" icon={<Database24Regular />}>Scammer Database</Tab>
          <Tab value="about" icon={<Info24Regular />}>About</Tab>
        </TabList>
      </div>

      <div className={styles.content}>
        {tab === 'analyze' && <AnalyzePage />}
        {tab === 'database' && <DatabasePage />}
        {tab === 'about' && <AboutPage />}
      </div>
    </div>
  );
}
