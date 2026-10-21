import Link from 'next/link';
import { resolveDocPage } from '@/lib/sections';
import styles from './home.module.css';

interface Feature {
  title: string;
  body: string;
  /** Candidate slugs under /docs, most specific first; the first that exists is linked. */
  pages: string[];
  preview?: boolean;
}

// Eight things DefenseClaw does. A tile is marked Preview when it is not
// verified live on every OS in this release (see /docs/support-matrix).
const FEATURES: Feature[] = [
  {
    title: 'Guardrails',
    body: 'Start in observe, switch to action, and block risky tool calls before they run.',
    pages: ['features/guardrail', 'guardrail'],
  },
  {
    title: 'Skill and MCP scanning',
    body: 'Check skills and MCP servers before an agent can load them.',
    pages: ['features/scanning', 'scanning/skill-scanner'],
  },
  {
    title: 'AI and runtime discovery',
    body: 'Find the agents, local models, MCP servers and skills on a machine, and see which ones ran.',
    pages: ['features/ai-discovery', 'ai-discovery'],
  },
  {
    title: 'Human approval',
    body: 'Pause a high-risk action for a person to approve, where the agent supports it.',
    pages: ['features/hitl', 'hitl'],
  },
  {
    title: 'Observability',
    body: 'Send every decision over OTLP to Grafana or Galileo, or to a webhook.',
    pages: ['features/observability', 'observability'],
  },
  {
    title: 'Policy creator',
    body: 'Build a policy section by section in the browser and copy the YAML into your config.',
    pages: ['features/policies/creator', 'policies/creator'],
  },
  {
    title: 'Terminal UI',
    body: 'Alerts, scans and setup in one terminal app on every OS. A macOS menu-bar app is in preview.',
    pages: ['features/tui', 'tui'],
  },
  {
    title: 'OpenShell sandboxes',
    body: 'Run a coding agent in an NVIDIA OpenShell sandbox on Linux or an Apple-silicon Mac, with every tool call judged.',
    pages: ['features/sandboxes', 'sandboxes'],
    preview: true,
  },
];

export function FeatureGrid() {
  const features = FEATURES.flatMap((feature) => {
    const href = resolveDocPage(feature.pages);
    return href ? [{ ...feature, href }] : [];
  });
  return (
    <ul className={styles.features}>
      {features.map((feature) => (
        <li key={feature.title}>
          <Link href={feature.href} className={styles.feature}>
            <strong className={styles.featureTitle}>
              {feature.title}
              {feature.preview ? <span className={styles.preview}>Preview</span> : null}
            </strong>
            <span className={styles.featureBody}>{feature.body}</span>
          </Link>
        </li>
      ))}
    </ul>
  );
}
