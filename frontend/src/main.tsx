import './styles/base.css'
import { StrictMode, lazy, Suspense } from 'react'
import { createRoot } from 'react-dom/client'
import { RouterProvider } from '@tanstack/react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { loader as monacoLoader } from '@monaco-editor/react'
import { router } from './router'

// Point the Monaco loader at the self-hosted bundle under /monaco/vs so
// the editor obeys the CSP `script-src 'self' blob:; connect-src 'self'`
// policy. Without this override @monaco-editor/loader fetches the runtime
// from cdn.jsdelivr.net which the CSP blocks, breaking every <CodeEditor>.
// The bytes ship via scripts/copy-monaco.mjs (prebuild) with a SHA-256
// integrity check against monaco-runtime.sha256.
monacoLoader.config({ paths: { vs: '/monaco/vs' } })

const ReactQueryDevtools = import.meta.env.DEV
  ? lazy(() =>
      import('@tanstack/react-query-devtools').then((m) => ({
        default: m.ReactQueryDevtools,
      }))
    )
  : () => null

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: true,
      retry: 1,
    },
  },
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
      <Suspense>
        <ReactQueryDevtools />
      </Suspense>
    </QueryClientProvider>
  </StrictMode>,
)
