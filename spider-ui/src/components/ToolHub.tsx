import { NavLink } from 'react-router-dom';
import { hubTiles } from '../app/environments';
import { Badge, Icon } from './Workbench';

/** Screen 2: Tool hub with 6 tiles and Results / Guide links */
export function ToolHub() {
  const toneMap = {
    Ready: 'cyan' as const,
    Preview: 'amber' as const,
    'Coming soon': 'amber' as const,
    Guide: 'neutral' as const,
  };

  return (
    <div className="page hub">
      <header className="hub__head">
        <p className="eyebrow">Welcome to SPIDER</p>
        <h1>What do you want to do?</h1>
        <p>Pick a tool. Each one opens in its own space and shares the same scan records.</p>
      </header>

      <ul className="hub__grid">
        {hubTiles.map((tile, i) => (
          <li key={tile.id}>
            <NavLink className="hub__tile" to={tile.path}>
              <span className="hub__index">0{i + 1}</span>
              <Icon
                name={
                  tile.id === 'scanner'
                    ? 'scanner'
                    : tile.id === 'hunter'
                    ? 'environment'
                    : tile.id === 'extension'
                    ? 'shield'
                    : tile.id === 'research'
                    ? 'models'
                    : tile.id === 'redteam'
                    ? 'lab'
                    : 'history'
                }
                className="hub__icon"
              />
              <h2>{tile.name}</h2>
              <p>{tile.tagline}</p>
              <ul className="hub__chips">
                {tile.includes.map((c) => (
                  <li key={c}>{c}</li>
                ))}
              </ul>
              <Badge tone={toneMap[tile.status]}>{tile.status}</Badge>
            </NavLink>
          </li>
        ))}
      </ul>

      <div style={{ textAlign: 'center', marginTop: 'var(--space-6)', display: 'flex', justifyContent: 'center', gap: 'var(--space-6)', flexWrap: 'wrap' }}>
        <NavLink className="text-link" to="/research">
          <strong>Results</strong> — How well does SPIDER do? Measured numbers and limits
        </NavLink>
        <NavLink className="text-link" to="/learn">
          <strong>How packages attack</strong> — Attack vectors in four steps
        </NavLink>
      </div>

      <p className="hub__foot">Static analysis only. 'None detected in this scan' does not mean the package is safe.</p>
    </div>
  );
}
