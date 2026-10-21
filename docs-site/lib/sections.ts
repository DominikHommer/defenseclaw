import { source } from '@/lib/source';
import { basePath } from '@/lib/site';

/**
 * The documentation sections, in reading order. The navbar, the landing
 * page's section index and the footer all read this list, so a section
 * added to content/docs shows up in every place at once.
 *
 * Each section lists candidate pages, most specific first. At build time
 * the first candidate that exists wins; a section with no existing page is
 * left out instead of linking to a 404. That lets the content tree grow
 * (or move) without touching the site shell.
 */

export interface DocLink {
  title: string;
  description: string;
  href: string;
  /** A raw file URL such as llms.txt, rendered as a plain <a>. */
  file?: boolean;
}

interface Candidate {
  title: string;
  description: string;
  /** Slugs under /docs, most specific first. */
  pages: string[];
  /** Raw file served next to the docs (not a docs page). */
  file?: string;
}

const SECTIONS: Candidate[] = [
  {
    title: 'Get started',
    description: 'Install DefenseClaw, set up an agent and see your first block.',
    pages: ['get-started', 'get-started/quickstart'],
  },
  {
    title: 'Features',
    description: 'Guardrails, policies, scanning, discovery, approvals and sandboxes.',
    pages: ['features', 'guardrail'],
  },
  {
    title: 'How-to guides',
    description: 'Step-by-step guides for common jobs.',
    pages: ['how-to', 'stories'],
  },
  {
    title: 'Troubleshooting',
    description: 'Find and fix install, hook and gateway problems.',
    pages: ['troubleshooting'],
  },
  {
    title: 'Reference',
    description: 'Commands, configuration, environment variables and APIs.',
    pages: ['reference', 'reference/cli'],
  },
  {
    title: 'Appendix',
    description: 'Benchmarks, compatibility tables and background detail.',
    pages: ['appendix'],
  },
  {
    title: 'For agents',
    description: 'The docs in plain Markdown for AI agents to read.',
    pages: ['for-agents'],
    file: '/llms.txt',
  },
];

// Feature areas for the navbar's Features menu, in the same order as the
// landing page's feature list.
const FEATURES: Candidate[] = [
  { title: 'Connectors', description: 'One page per supported AI agent.', pages: ['features/connectors', 'connectors'] },
  { title: 'Guardrails', description: 'Observe, then block risky tool calls.', pages: ['features/guardrail', 'guardrail'] },
  { title: 'Policies', description: 'Rules, thresholds and admission checks.', pages: ['features/policies', 'policies'] },
  { title: 'Skill and MCP scanning', description: 'Check skills and MCP servers before they load.', pages: ['features/scanning', 'scanning', 'scanning/skill-scanner'] },
  { title: 'AI discovery', description: 'Find the agents, models and MCP servers on a machine.', pages: ['features/ai-discovery', 'ai-discovery'] },
  { title: 'Human approval', description: 'Pause a high-risk action for a person to approve.', pages: ['features/hitl', 'hitl'] },
  { title: 'Observability', description: 'Send every decision over OTLP or to a webhook.', pages: ['features/observability', 'observability'] },
  { title: 'OpenShell sandboxes', description: 'Run an agent inside an NVIDIA OpenShell sandbox.', pages: ['features/sandboxes', 'sandboxes'] },
];

/** URL of the first existing docs page among `slugs`, or null. */
export function resolveDocPage(slugs: string[]): string | null {
  for (const slug of slugs) {
    const page = source.getPage(slug.split('/').filter(Boolean));
    if (page) return page.url;
  }
  return null;
}

function resolve(list: Candidate[]): DocLink[] {
  const out: DocLink[] = [];
  for (const item of list) {
    const href = resolveDocPage(item.pages);
    if (href) out.push({ title: item.title, description: item.description, href });
    else if (item.file) out.push({ title: item.title, description: item.description, href: `${basePath}${item.file}`, file: true });
  }
  return out;
}

export const docSections: DocLink[] = resolve(SECTIONS);
export const featureLinks: DocLink[] = resolve(FEATURES);

/** The resolved section with this title, if it exists in this build. */
export function docSection(title: string): DocLink | undefined {
  return docSections.find((section) => section.title === title);
}
