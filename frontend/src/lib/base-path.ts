// The SPA can be served under a URL prefix (e.g. /osctrl/). The prefix is a
// deploy-time setting: the web server rewrites <base href> in index.html, so
// one build serves any prefix. /api stays unprefixed. Hard-coded absolute
// paths (location redirects, <img src>) must go through appPath().

/** "/osctrl" for a document base of http://h/osctrl/, "" at the root. */
export function basePathFrom(baseURI: string): string {
  try {
    return new URL(baseURI).pathname.replace(/\/+$/, '')
  } catch {
    return ''
  }
}

export function appPathFor(basePath: string, path: string): string {
  return basePath + path
}

export const basePath = basePathFrom(typeof document === 'undefined' ? '' : document.baseURI)

/** Prefix an absolute in-app path ("/login") with the deploy prefix. */
export const appPath = (path: string): string => appPathFor(basePath, path)
