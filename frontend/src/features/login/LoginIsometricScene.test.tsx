import { render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { LoginIsometricScene } from './LoginIsometricScene';

describe('LoginIsometricScene', () => {
  it('layers the supplied control tower over the circuit field', () => {
    const { container } = render(<LoginIsometricScene />);

    expect(container.querySelector('.login-scene-circuit-plane')).not.toBeNull();
    expect(container.querySelector('image[href="/img/circuit.svg"]')).not.toBeNull();
    expect(
      container.querySelector('image[href="/img/osquery-control-tower-simple.png"]'),
    ).toHaveClass('login-scene-control-tower');
  });
});
