import Link from 'next/link';
import { docSections } from '@/lib/sections';
import styles from './home.module.css';

/**
 * The documentation sections as a short index beside the hero, so the first
 * screen says where everything is. Reads lib/sections.ts, which drops a
 * section that has no page in this build.
 */
export function DocMap({ className }: { className?: string }) {
  return (
    <nav className={className ? `${styles.docMap} ${className}` : styles.docMap} aria-labelledby="docmap-heading">
      <h2 id="docmap-heading" className={styles.docMapTitle}>Documentation</h2>
      <ul className={styles.docMapList}>
        {docSections.map((section) => (
          <li key={section.title}>
            {section.file ? (
              <a href={section.href}>
                <strong>{section.title}</strong>
                <span>{section.description}</span>
              </a>
            ) : (
              <Link href={section.href}>
                <strong>{section.title}</strong>
                <span>{section.description}</span>
              </Link>
            )}
          </li>
        ))}
      </ul>
    </nav>
  );
}
