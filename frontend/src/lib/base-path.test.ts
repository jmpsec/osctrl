import { describe, expect, it, vi } from 'vitest'
import { appPathFor, basePathFrom } from './base-path'

describe('basePathFrom', () => {
  it.each([
    ['http://h/', ''],
    ['http://h/osctrl/', '/osctrl'],
    ['http://h/a/b/', '/a/b'],
    ['http://h/osctrl', '/osctrl'],
    ['', ''],
  ])('%s -> %j', (uri, want) => {
    expect(basePathFrom(uri)).toBe(want)
  })
})

describe('appPathFor', () => {
  it('prefixes absolute app paths', () => {
    expect(appPathFor('/osctrl', '/login')).toBe('/osctrl/login')
    expect(appPathFor('/osctrl', '/img/a.png')).toBe('/osctrl/img/a.png')
  })
  it('is the identity at the root', () => {
    expect(appPathFor('', '/login')).toBe('/login')
  })
})

describe('module-level basePath', () => {
  it('follows <base href> of the document', async () => {
    const el = document.createElement('base')
    el.href = 'http://localhost/osctrl/'
    document.head.appendChild(el)
    vi.resetModules()
    const m = await import('./base-path')
    expect(m.basePath).toBe('/osctrl')
    expect(m.appPath('/api/v1/login')).toBe('/osctrl/api/v1/login')
    el.remove()
  })
})
