import { useState, useEffect } from 'react';
import {
  makeStyles,
  tokens,
  Card,
  Text,
  Button,
  Badge,
} from '@fluentui/react-components';
import { getTemplates } from '../api/client';

const useStyles = makeStyles({
  container: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
    marginTop: '16px',
  },
  heading: {
    fontSize: '14px',
    fontWeight: 600,
    color: tokens.colorNeutralForeground2,
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
    gap: '8px',
  },
  card: {
    padding: '12px',
    cursor: 'pointer',
    ':hover': {
      backgroundColor: tokens.colorNeutralBackground1Hover,
    },
  },
  cardHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '4px',
  },
  templateName: {
    fontWeight: 600,
    fontSize: '13px',
  },
  description: {
    fontSize: '12px',
    color: tokens.colorNeutralForeground3,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    display: '-webkit-box',
    WebkitLineClamp: 2,
    WebkitBoxOrient: 'vertical',
  },
});

interface Template {
  id: number;
  category: string;
  template_name: string;
  message_text: string;
  sender_number: string;
  description: string;
}

interface DemoMessagesProps {
  onSelect: (message: string, phoneNumber: string) => void;
}

export default function DemoMessages({ onSelect }: DemoMessagesProps) {
  const styles = useStyles();
  const [templates, setTemplates] = useState<Template[]>([]);

  useEffect(() => {
    getTemplates().then(data => setTemplates(data.templates)).catch(() => {});
  }, []);

  if (templates.length === 0) return null;

  const categoryColor = (cat: string): 'danger' | 'warning' | 'success' | 'informative' => {
    if (cat === 'legitimate_business') return 'success';
    if (cat === 'romance') return 'warning';
    return 'danger';
  };

  return (
    <div className={styles.container}>
      <Text className={styles.heading}>Quick Demo - Click to load a sample message:</Text>
      <div className={styles.grid}>
        {templates.map(t => (
          <Card
            key={t.id}
            className={styles.card}
            onClick={() => onSelect(t.message_text, t.sender_number)}
          >
            <div className={styles.cardHeader}>
              <span className={styles.templateName}>{t.template_name}</span>
              <Badge size="small" color={categoryColor(t.category)}>
                {t.category.replace(/_/g, ' ')}
              </Badge>
            </div>
            <Text className={styles.description}>{t.description}</Text>
          </Card>
        ))}
      </div>
    </div>
  );
}
