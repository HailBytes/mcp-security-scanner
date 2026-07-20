import { isLoopbackHost, isLoopbackUrl } from '../net';

describe('isLoopbackHost', () => {
  it.each([
    'localhost',
    'LOCALHOST',
    'app.localhost',
    '127.0.0.1',
    '127.1.2.3',
    '127.255.255.255',
    '::1',
    '0:0:0:0:0:0:0:1',
    '[::1]',
    '::1%eth0',
  ])('treats "%s" as loopback', (host) => {
    expect(isLoopbackHost(host)).toBe(true);
  });

  it.each([
    'example.com',
    'notlocalhost',
    'localhost.evil.com',
    '128.0.0.1',
    '126.255.255.255',
    '10.0.0.1',
    '0.0.0.0', // "all interfaces" bind address — reachable over the network.
    '::',
    '169.254.0.1',
  ])('treats "%s" as non-loopback', (host) => {
    expect(isLoopbackHost(host)).toBe(false);
  });
});

describe('isLoopbackUrl', () => {
  it.each([
    'http://localhost:3000',
    'http://127.0.0.1:8080/mcp',
    'ws://localhost:8080',
    'http://[::1]:3000',
    'https://localhost', // loopback regardless of scheme
  ])('treats "%s" as a loopback URL', (url) => {
    expect(isLoopbackUrl(url)).toBe(true);
  });

  it.each([
    'http://example.com',
    'ws://public-server.example.com',
    'http://0.0.0.0:3000',
    'not a url',
    'stdio:///usr/bin/my-server',
  ])('treats "%s" as a non-loopback URL', (url) => {
    expect(isLoopbackUrl(url)).toBe(false);
  });
});
