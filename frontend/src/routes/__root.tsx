import { createRootRoute, Outlet } from '@tanstack/react-router'
import { lazy, Suspense } from 'react'

const TanStackRouterDevtools =
  import.meta.env.DEV
    ? lazy(() =>
        import('@tanstack/router-devtools').then((m) => ({
          default: m.TanStackRouterDevtools,
        }))
      )
    : () => null

export const rootRoute = createRootRoute({
  component: () => (
    <>
      <Outlet />
      <Suspense>
        <TanStackRouterDevtools />
      </Suspense>
    </>
  ),
})
