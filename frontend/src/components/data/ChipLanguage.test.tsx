import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { StatusBadge } from './StatusBadge';
import { TagChip } from './TagChip';
import { FilterChip } from './FilterChip';
import { MetadataBadge } from './MetadataBadge';
import { PlatformIcon } from './PlatformIcon';
import { SelectionChip } from './SelectionChip';

describe('chip language', () => {
  it('renders status as a dot-led sentence-case label without a pill surface', () => {
    render(<StatusBadge variant="success" label="Healthy" />);

    expect(screen.getByText('Healthy')).toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'active' })).toBeInTheDocument();
    expect(screen.getByText('Healthy').parentElement).not.toHaveClass('rounded-full');
  });

  it('preserves authored tag casing on a neutral metadata surface', () => {
    render(<TagChip label="Incident-Response" color="#5b8def" />);

    expect(screen.getByText('Incident-Response')).toBeInTheDocument();
    expect(screen.getByText('Incident-Response').parentElement).toHaveClass('rounded');
  });

  it('exposes filters as pressed-state controls with attached counts', () => {
    render(<FilterChip label="Linux" selected count={24} />);

    expect(screen.getByRole('button', { name: 'Linux 24' })).toHaveAttribute('aria-pressed', 'true');
  });

  it('supports recognizable platform marks without changing the filter label', () => {
    render(<FilterChip label="Linux" icon={<PlatformIcon platform="linux" />} />);

    const chip = screen.getByRole('button', { name: 'Linux' });
    expect(chip.querySelector('svg')).toBeInTheDocument();
    expect(chip).toHaveAttribute('aria-pressed', 'false');
  });

  it('keeps categorical metadata neutral', () => {
    render(<MetadataBadge>Admin</MetadataBadge>);

    expect(screen.getByText('Admin')).toHaveClass('normal-case');
    expect(screen.queryByRole('img')).not.toBeInTheDocument();
  });

  it('gives committed selections an explicit remove action', async () => {
    const onRemove = vi.fn();
    const user = userEvent.setup();
    render(<SelectionChip label="web-server-01" onRemove={onRemove} />);

    await user.click(screen.getByRole('button', { name: 'Remove web-server-01' }));
    expect(onRemove).toHaveBeenCalledOnce();
  });
});
