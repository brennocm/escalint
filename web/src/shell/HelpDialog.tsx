import { useEffect, useRef } from 'react';

export const shortcuts: readonly (readonly [string, string])[] = [
  ['Ctrl/⌘ + K', 'Search principals, ARNs, rules, techniques and paths'],
  ['?', 'Show this list'],
  [
    'g o / g a / g f / g e / g x / g t',
    'Go to Overview, Atlas, Findings, Exposure, Fix plan, Detect',
  ],
  ['t', 'Toggle light / dark theme'],
  ['p', 'Toggle pseudonyms (hide names for screenshots)'],
  ['Escape', 'Close dialogs, clear the selection'],
  ['Arrow keys', 'Move between nodes in Trace and Reach'],
  ['Shift + click', 'Atlas: shortest path between two nodes'],
];

export function HelpDialog({ onClose }: { readonly onClose: () => void }) {
  const close = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    close.current?.focus();
  }, []);
  return (
    <div
      className="overlay"
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="dialog" role="dialog" aria-modal="true" aria-labelledby="help-title">
        <h2 id="help-title">Keyboard shortcuts</h2>
        <table className="table">
          <tbody>
            {shortcuts.map(([key, what]) => (
              <tr key={key}>
                <th scope="row">
                  <kbd>{key}</kbd>
                </th>
                <td>{what}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <button ref={close} type="button" className="button" onClick={onClose}>
          Close
        </button>
      </div>
    </div>
  );
}
