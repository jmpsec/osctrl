import { createRoute } from '@tanstack/react-router';
import { envRoute } from './route';
import { TagsPage } from '$/features/tags/TagsPage';

export const envTagsRoute = createRoute({
  getParentRoute: () => envRoute,
  path: 'tags',
  component: TagsPage,
});
