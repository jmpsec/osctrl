import { createRoute, redirect } from '@tanstack/react-router';
import { rootRoute } from './__root';
import { ComponentGallery } from '$/features/dev/ComponentGallery';

// DEV-only route. In a production build (import.meta.env.DEV === false),
// any attempt to navigate here redirects to "/" so it never appears.
export const devComponentsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/dev/components',
  beforeLoad() {
    if (!import.meta.env.DEV) {
      throw redirect({ to: '/' });
    }
  },
  component: ComponentGallery,
});
