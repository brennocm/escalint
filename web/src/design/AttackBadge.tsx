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
  const url = `https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/`;
  return (
    <a className="attack-badge" href={url} target="_blank" rel="noopener noreferrer">
      <span className="attack-badge__id">{techniqueId}</span>
      <span className="attack-badge__name">{name}</span>
      <span className="attack-badge__tactics">{tactics.join(' · ')}</span>
    </a>
  );
}
