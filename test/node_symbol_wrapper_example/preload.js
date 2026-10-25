'use strict';

/**
 * preload.js -- run before the guest with:
 *
 *     node --require ./preload.js ./guest.js
 *
 * The guest sees the real `fs`, `child_process` and `os` modules, but selected
 * properties have already been replaced by same-name proxies.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const childProcess = require('child_process');

const { Interposer, Policy } = require('./interpose');

const DEMO_DIR = '/tmp/symbol-wrapper-demo';
const DEMO_FILE = path.join(DEMO_DIR, 'hello.txt');

// Node's CommonJS loader itself calls fs.readFileSync() to load the entry
// script *after* --require has run.  Allow exactly that file through, or the
// guest never starts.  This is also why the binding is not a security boundary.
const MAIN_FILE = process.argv[1]
  ? path.resolve(process.argv[1])
  : path.resolve(__dirname, 'guest.js');

// Use the real fs before it is bound.
fs.mkdirSync(DEMO_DIR, { recursive: true });
fs.writeFileSync(DEMO_FILE, 'hello from an allowed read\n', 'utf8');

function ask(capId, args) {
  if (capId === 'child_process.execSync') {
    const command = String(args[0] ?? '');
    // Only a harmless echo/printf is approved in this demo.
    return /^echo(?:\s|$)/.test(command) || /^printf(?:\s|$)/.test(command);
  }
  return false;
}

function audit(event) {
  console.log(
    `[audit] ${String(event.decision).padEnd(10)} ${event.cap} argc=${event.argc}`,
  );
}

const guard = new Interposer({
  defaultPolicy: Policy.DENY,
  ask,
  audit,
});

// ---------------------------------------------------------------------------
// Bind names on modules that are already loaded.
// ---------------------------------------------------------------------------

guard.bindModule('fs', 'readFileSync', 'fs.readFileSync', {
  policy: (cap, args) => {
    const file = String(args[0] ?? '');
    const resolved = path.resolve(file);
    // Let Node's own CommonJS loader read the entry script.
    if (resolved === MAIN_FILE) {
      return Policy.ALLOW;
    }
    return resolved.startsWith(DEMO_DIR + path.sep) ? Policy.ALLOW : Policy.DENY;
  },
  description: 'read only from the demo directory',
});

guard.bindModule('child_process', 'execSync', 'child_process.execSync', {
  policy: Policy.ASK,
  description: 'shell execution needs approval',
});

guard.bindModule('os', 'hostname', 'os.hostname', {
  policy: Policy.SUBSTITUTE,
  substitute: () => 'sandbox-host',
  description: 'fake hostname',
});

// ---------------------------------------------------------------------------
// Gate require() and bind names on modules that are loaded later.
// ---------------------------------------------------------------------------

const DENIED_MODULES = new Set([
  'module',
  'vm',
  'worker_threads',
  'net',
  'http',
  'https',
  'dgram',
  'tls',
  'dns',
  'cluster',
  'inspector',
  'repl',
]);

guard.installLoader({
  check(request) {
    // Do not let the guest pull in our own preload/core by path.
    if (request.startsWith('.') || request.startsWith('/')) {
      return Policy.DENY;
    }
    return DENIED_MODULES.has(request) ? Policy.DENY : Policy.ALLOW;
  },
  bindings: {
    // Applied when the guest first requires zlib.  The module may already be
    // cached by Node; the hook still runs on the guest's require() call.
    zlib: [
      {
        name: 'deflateSync',
        capId: 'zlib.deflateSync',
        spec: {
          policy: Policy.DENY,
          description: 'compression disabled by the demo',
        },
      },
    ],
  },
});

guard.seal();

console.log(
  `[preload] installed ${guard.describe().length} initial binding(s) and a require hook`,
);
for (const item of guard.describe()) {
  console.log(`[preload]   ${item.cap.padEnd(28)} ${item.description}`);
}
console.log('[preload] running guest\n');
