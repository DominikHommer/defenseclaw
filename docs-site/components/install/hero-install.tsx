'use client';

import Link from 'next/link';
import { cn } from '@/lib/utils';
import { DOWNLOADS, INIT_COMMAND } from '@/data/downloads';
import { InstallCommand } from './install-command';
import { OsSwitcher } from './os-switcher';
import { useOs } from './use-os';
import styles from './install.module.css';

/**
 * The landing hero's install surface: one OS-aware command, large, with the
 * OS choice attached to it. The next step (init) and the full runbook are
 * one line below, so the first screen answers "how do I install it".
 */
export function HeroInstall({ className }: { className?: string }) {
  const [os] = useOs();
  const download = DOWNLOADS[os];
  const prompt = download.shell === 'powershell' ? 'PS>' : '$';

  return (
    <div className={cn(styles.heroInstall, className)}>
      <div className={styles.heroInstallHead}>
        <h2 id="install-heading" className={styles.heroInstallTitle}>
          Install for your user on {download.label}
        </h2>
        <OsSwitcher className={styles.heroInstallOs} />
      </div>
      <InstallCommand
        className={styles.heroInstallCmd}
        command={download.install}
        prompt={prompt}
        size="lg"
        copyLabel={`Copy the ${download.label} install command`}
      />
      <p className={styles.heroInstallNext}>
        Then run <code>{INIT_COMMAND}</code> to set up the agents it finds, in observe mode.
      </p>
      <p className={styles.heroInstallLinks}>
        <Link href="/docs/get-started/quickstart">Follow the 5-minute quickstart</Link>
        <Link href="/docs/get-started/download">All downloads and checksums</Link>
      </p>
    </div>
  );
}
