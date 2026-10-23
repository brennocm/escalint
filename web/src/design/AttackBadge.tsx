// ATT&CK technique IDs: T1234 or T1234.001. Anything else (for example a
// tampered analysis.json) is shown as text without a link.
const techniqueIdPattern = /^T\d{4}(\.\d{3})?$/;

export function attackUrl(techniqueId: string): string | null {
  if (!techniqueIdPattern.test(techniqueId)) {
    return null;
  }
  return `https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/`;
}

/** MITRE ATT&CK technique badge: text first, never icon-only. The link is
 * user-initiated navigation; the app itself never fetches attack.mitre.org. */
export function AttackBadge({
  techniqueId,
  name,
  tactics,
}: {
  techniqueId: string;
  name: string;
  tactics: string[];
}) {
  const url = attackUrl(techniqueId);
  const content = (
    <>
      <span className="attack-badge__id">{techniqueId}</span>
      <span className="attack-badge__name">{name}</span>
      <span className="attack-badge__tactics">{tactics.join(' · ')}</span>
    </>
  );
  if (url === null) {
    return <span className="attack-badge">{content}</span>;
  }
  return (
    <a className="attack-badge" href={url} target="_blank" rel="noopener noreferrer">
      {content}
    </a>
  );
}
