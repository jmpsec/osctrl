import { createRouter } from '@tanstack/react-router'
import { rootRoute } from './routes/__root'
import { indexRoute } from './routes/index'
import { loginRoute } from './routes/login'
import { appRoute } from './routes/_app/route'
import { appIndexRoute } from './routes/_app/index'
import { envRoute } from './routes/_app/env/$env/route'
import { envIndexRoute } from './routes/_app/env/$env/index'
import { envNodesRoute } from './routes/_app/env/$env/nodes'
import { envNodeDetailRoute } from './routes/_app/env/$env/nodes.$uuid'
import { envQueriesRoute } from './routes/_app/env/$env/queries'
import { envQueryNewRoute } from './routes/_app/env/$env/queries.new'
import { envQueryDetailRoute } from './routes/_app/env/$env/queries.$name'
import { envSavedQueriesRoute } from './routes/_app/env/$env/saved-queries'
import { envCarvesRoute } from './routes/_app/env/$env/carves'
import { envCarveNewRoute } from './routes/_app/env/$env/carves.new'
import { envCarveDetailRoute } from './routes/_app/env/$env/carves.$name'
import { envTagsRoute } from './routes/_app/env/$env/tags'
import { envConfigRoute } from './routes/_app/env/$env/config'
import { envEnrollRoute } from './routes/_app/env/$env/enroll'
import { usersRoute } from './routes/_app/users'
import { profileRoute } from './routes/_app/profile'
import { environmentsRoute } from './routes/_app/environments'
import { settingsServiceRoute } from './routes/_app/settings.$service'
import { auditRoute } from './routes/_app/audit'
import { devComponentsRoute } from './routes/dev.components'

const routeTree = rootRoute.addChildren([
  indexRoute,
  loginRoute,
  devComponentsRoute,
  appRoute.addChildren([
    appIndexRoute,
    usersRoute,
    profileRoute,
    environmentsRoute,
    settingsServiceRoute,
    auditRoute,
    envRoute.addChildren([
      envIndexRoute,
      envNodesRoute,
      envNodeDetailRoute,
      envQueriesRoute,
      envQueryNewRoute,
      envQueryDetailRoute,
      envSavedQueriesRoute,
      envCarvesRoute,
      envCarveNewRoute,
      envCarveDetailRoute,
      envTagsRoute,
      envConfigRoute,
      envEnrollRoute,
    ]),
  ]),
])

export const router = createRouter({ routeTree })

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
