'use strict';

/**
 * guest.js -- normal plaintext JavaScript.  It does not know that any of these
 * names were replaced.
 */

const fs = require('fs');
const childProcess = require('child_process');
const os = require('os');

function describeError(error) {
  return `${error.code || error.name}: ${error.message}`;
}

function call(label, fn) {
  try {
    const value = fn();
    console.log(`${label} ${value}`);
  } catch (error) {
    console.log(`${label} DENIED -> ${describeError(error)}`);
  }
}

// 1. SUBSTITUTE
call('[guest] os.hostname() ->', () => os.hostname());

// 2. ALLOW / DENY by path
call('[guest] read demo file ->', () =>
  fs.readFileSync('/tmp/symbol-wrapper-demo/hello.txt', 'utf8').trim(),
);
call('[guest] read /etc/hosts ->', () =>
  fs.readFileSync('/etc/hosts', 'utf8').split('\n')[0],
);

// 3. ASK
call('[guest] execSync echo ->', () =>
  String(childProcess.execSync('echo "[guest] execSync allowed by ASK"')).trim(),
);
call('[guest] execSync rm ->', () =>
  String(childProcess.execSync('rm -rf /tmp/definitely-not-real')),
);

// 4. Module loaded after the hook, then lazily bound.
try {
  const zlib = require('zlib');
  call('[guest] zlib.deflateSync ->', () =>
    zlib.deflateSync(Buffer.from('x')).toString('hex'),
  );
} catch (error) {
  console.log(`[guest] require(zlib) -> ${describeError(error)}`);
}

// 5. Plaintext bypasses: these names were not bound.

// fs.readFile is a sibling of fs.readFileSync.
fs.readFile('/etc/hosts', 'utf8', (error, data) => {
  if (error) {
    console.log(`[guest] fs.readFile bypass error -> ${describeError(error)}`);
  } else {
    console.log('[guest] fs.readFile bypass ->', data.split('\n')[0]);
  }
});

// fs.promises.readFile is another sibling path.
fs.promises
  .readFile('/etc/hosts', 'utf8')
  .then((data) => {
    console.log('[guest] fs.promises.readFile bypass ->', data.split('\n')[0]);
  })
  .catch((error) => {
    console.log(
      `[guest] fs.promises.readFile bypass error -> ${describeError(error)}`,
    );
  });

// child_process.spawnSync and exec were not bound.
const spawned = childProcess.spawnSync('echo', ['[guest] spawnSync bypassed']);
console.log('[guest] spawnSync bypass ->', String(spawned.stdout).trim());

childProcess.exec('echo "[guest] exec bypassed"', (error, stdout) => {
  if (error) {
    console.log(`[guest] exec bypass error -> ${describeError(error)}`);
  } else {
    console.log('[guest] exec bypass ->', stdout.trim());
  }
});

// 6. require() policy: node: normalization and a denied built-in.
for (const name of ['net', 'node:net', 'module']) {
  try {
    require(name);
    console.log(`[guest] require(${name}) ALLOWED`);
  } catch (error) {
    console.log(`[guest] require(${name}) DENIED -> ${describeError(error)}`);
  }
}
