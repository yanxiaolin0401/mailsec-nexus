import { test } from 'node:test'
import process from 'node:process'
import assert from 'node:assert/strict'
import { createServer } from 'vite'
import { createServer as createHttpServer } from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

test('missing socket override uses private IPC, never the retired TCP port', async () => {
  const previous = process.env.PLATFORM_API_SOCKET
  delete process.env.PLATFORM_API_SOCKET
  let server
  try {
    server = await createServer({configFile:'vite.config.ts', logLevel:'silent'})
    const target = server.config.server.proxy['/api'].target
    assert.equal(typeof target, 'object')
    assert.equal(target.socketPath, join(process.cwd(), '../.local/platform-api.sock'))
  } finally {
    if (server) await server.close()
    if (previous === undefined) delete process.env.PLATFORM_API_SOCKET
    else process.env.PLATFORM_API_SOCKET = previous
  }
})

test('deployment files never reach Vite JS transform, including query and fs URLs', async () => {
  const server = await createServer({
    configFile: 'vite.config.ts',
    server: { host: '127.0.0.1', port: 0, strictPort: true },
    logLevel: 'silent',
  })
  await server.listen()
  try {
    const base = `http://127.0.0.1:${server.httpServer.address().port}`
    for (const path of [
      '/Dockerfile', '/Dockerfile?import', '/Dockerfile?raw',
      '/%44ockerfile?import', `/@fs/${process.cwd()}/Dockerfile?import`,
    ]) {
      const response = await fetch(base + path)
      assert.equal(response.status, 403, path)
      assert.doesNotMatch(await response.text(), /Failed to parse source for import analysis/)
    }
    assert.equal((await fetch(base + '/')).status, 200)
    assert.equal((await fetch(base + '/src/main.tsx')).status, 200)
  } finally {
    await server.close()
  }
})

test('platform API uses a private socket while Vite alone exposes a TCP listener', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mailsec-vite-ipc-'))
  const socket = join(dir, 'api.sock')
  const upstream = createHttpServer((req, res) => {
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({path: req.url}))
  })
  await new Promise(resolve => upstream.listen(socket, resolve))
  const previous = process.env.PLATFORM_API_SOCKET
  process.env.PLATFORM_API_SOCKET = socket
  let server
  try {
    server = await createServer({configFile:'vite.config.ts',server:{host:'127.0.0.1',port:0,strictPort:true},logLevel:'silent'})
    await server.listen()
    const response = await fetch(`http://127.0.0.1:${server.httpServer.address().port}/api/platform/v1/test`)
    assert.equal(response.status, 200)
    assert.deepEqual(await response.json(), {path:'/api/platform/v1/test'})
  } finally {
    if (server) await server.close()
    await new Promise(resolve => upstream.close(resolve))
    if (previous === undefined) delete process.env.PLATFORM_API_SOCKET
    else process.env.PLATFORM_API_SOCKET = previous
    rmSync(dir, {recursive:true,force:true})
  }
})
