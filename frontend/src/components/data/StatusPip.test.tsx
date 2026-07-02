import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { StatusPip } from './StatusPip';

describe('StatusPip', () => {
  it('renders a single live activity beacon when live', () => {
    const { container } = render(<StatusPip variant="success" live />);

    expect(screen.getByRole('img', { name: 'active' })).toHaveClass('pip-live');
    expect(container.querySelectorAll('.pip-live-ring')).toHaveLength(1);
  });
});
