'use strict';

/**
 * interpose.js -- a small, standalone "same-name API interception" core for Node.
 *
 * The guest keeps writing normal code:
 *
 *     const fs = require('fs');
 *     fs.readFileSync(path);
 *
 * The guard replaces the *value* of `fs.readFileSync` (the plaintext name) with
 * a proxy.  The proxy has the same `name`, `length` and, for constructors, the
 * same `prototype`, but the original function lives only in this module's
 * closure.  Node closures are not user-inspectable, so unlike the Python
 * example the original is not reachable through normal JS reflection.
 *
 * Decisions are the same as the Python core:
 *
 *     ALLOW       -> call the original
 *     DENY        -> throw CapabilityDenied
 *     ASK         -> ask a callback; deny unless it says yes
 *     SUBSTITUTE  -> return a fake value / call a fake function
 *
 * This is a mechanism, not a security boundary.  Sibling APIs, aliases captured
 * before binding, `process.binding`, `Module._extensions`, dynamic `import()`,
 * native addons, etc. all remain possible escape routes.
 */

const Policy = Object.freeze({
  ALLOW: 'ALLOW',
  DENY: 'DENY',
  ASK: 'ASK',
  SUBSTITUTE: 'SUBSTITUTE',
});

class CapabilityDenied extends Error {
  constructor(capId, reason = '') {
    const suffix = reason ? ` (${reason})` : '';
    super(`capability denied: ${capId}${suffix}`);
    this.name = 'CapabilityDenied';
    this.code = 'CAPABILITY_DENIED';
    this.capId = capId;
    this.reason = reason;
  }
}

class Interposer {
  constructor({ defaultPolicy = Policy.DENY, ask = null, audit = null } = {}) {
    this._defaultPolicy = defaultPolicy;
    this._ask = ask;
    this._audit = audit;

    this._caps = new Map();
    this._originals = new Map();
    this._proxies = new Map();
    this._bindings = [];
    this._undo = [];
    this._sealed = false;
    this._loaderInstalled = false;
  }

  // ------------------------------------------------------------------
  // Binding
  // ------------------------------------------------------------------

  bind(container, name, capId, spec = {}) {
    return this._bind(container, name, capId, spec, false);
  }

  bindModule(moduleName, name, capId, spec = {}) {
    // Explicit binding is normally done before installLoader(), so require()
    // here is the plain CommonJS require.
    return this.bind(require(moduleName), name, capId, spec);
  }

  bindGlobal(name, capId, spec = {}) {
    return this.bind(globalThis, name, capId, spec);
  }

  _bind(container, name, capId, spec = {}, internal = false) {
    if (this._sealed && !internal) {
      throw new Error('interposer is sealed; no new external bindings are allowed');
    }
    if (typeof container === 'string') {
      container = require(container);
    }
    if (
      container === null ||
      (typeof container !== 'object' && typeof container !== 'function')
    ) {
      throw new TypeError('container must be an object, function, or module name');
    }
    if (typeof name !== 'string' || name.length === 0) {
      throw new TypeError('name must be a non-empty string');
    }
    if (this._proxies.has(capId)) {
      return this._proxies.get(capId);
    }

    const original = container[name];
    if (typeof original !== 'function') {
      throw new TypeError(`cannot bind ${capId}: ${name} is not a function`);
    }

    const cap = {
      id: capId,
      policy: spec.policy === undefined ? this._defaultPolicy : spec.policy,
      substitute: spec.substitute,
      description: spec.description || '',
    };
    const proxy = this._makeProxy(capId, original);

    try {
      container[name] = proxy;
    } catch (error) {
      throw new Error(`cannot install binding ${capId}: ${error.message}`);
    }

    this._caps.set(capId, cap);
    this._originals.set(capId, original);
    this._proxies.set(capId, proxy);
    this._bindings.push({
      container,
      name,
      capId,
      original,
      description: cap.description,
    });
    this._undo.push(() => {
      if (container[name] === proxy) {
        container[name] = original;
      }
    });
    return proxy;
  }

  _makeProxy(capId, original) {
    const self = this;

    const proxy = function (...args) {
      // `new fs.SomeClass()` must still construct the real class.
      if (new.target) {
        return self._invokeConstruct(capId, args, new.target);
      }
      return self._invoke(capId, this, args);
    };

    try {
      Object.defineProperty(proxy, 'name', {
        value: original.name || capId,
        configurable: true,
      });
    } catch {
      // Metadata is best effort.
    }
    try {
      Object.defineProperty(proxy, 'length', {
        value: original.length,
        configurable: true,
      });
    } catch {
      // Metadata is best effort.
    }
    if (original.prototype && typeof original.prototype === 'object') {
      try {
        Object.defineProperty(proxy, 'prototype', {
          value: original.prototype,
          writable: false,
          configurable: false,
        });
      } catch {
        // Metadata is best effort.
      }
    }

    // Do not attach the original as a property.  The closure is the only
    // reference, and JS does not expose closure variables to user code.
    return Object.freeze(proxy);
  }

  // ------------------------------------------------------------------
  // Loader hook (the Node equivalent of Python's import hook)
  // ------------------------------------------------------------------

  /**
   * installLoader({ check, bindings })
   *
   * check(request, { request, parent, isMain }) -> Policy.ALLOW | Policy.DENY |
   *   Policy.ASK.  Anything other than ALLOW (and ASK that is approved) is
   *   denied.
   *
   * bindings: { "zlib": [{ name: "deflateSync", capId: "...", spec: {...} }] }
   *   Applied after the module is actually loaded, so this also works for
   *   modules that were already cached before the hook was installed.
   *
   * `isMain` is allowed because --require runs before the entry script is
   * loaded.  That is a real, documented hole: a guest could call
   * Module._load(..., true) to imitate the main load.  Do not treat this as a
   * security boundary.
   */
  installLoader({ check = null, bindings = {} } = {}) {
    if (this._loaderInstalled) {
      throw new Error('loader hook is already installed');
    }

    const Module = require('module');
    const originalLoad = Module._load;
    const apply = Reflect.apply;
    const self = this;

    const normalize = (request) =>
      typeof request === 'string' ? request.replace(/^node:/, '') : String(request);

    Module._load = function (request, parent, isMain) {
      const key = normalize(request);

      if (isMain) {
        return apply(originalLoad, this, [request, parent, isMain]);
      }

      let verdict = Policy.ALLOW;
      if (check) {
        try {
          verdict = check(key, { request, parent, isMain });
        } catch {
          throw new CapabilityDenied(`require:${key}`, 'policy error');
        }
      }

      if (verdict === Policy.ASK) {
        let approved = false;
        try {
          approved = Boolean(self._ask && self._ask(`require:${key}`, [key]));
        } catch {
          approved = false;
        }
        if (!approved) {
          throw new CapabilityDenied(`require:${key}`, 'ask denied');
        }
      } else if (verdict !== Policy.ALLOW) {
        throw new CapabilityDenied(`require:${key}`, 'denied by require policy');
      }

      const exports = apply(originalLoad, this, [request, parent, isMain]);

      const rules = bindings[key];
      if (
        rules &&
        exports !== null &&
        (typeof exports === 'object' || typeof exports === 'function')
      ) {
        for (const rule of rules) {
          if (typeof exports[rule.name] === 'function') {
            // internal=true: sealing only blocks external bind() calls.
            self._bind(exports, rule.name, rule.capId, rule.spec || {}, true);
          }
        }
      }

      return exports;
    };

    this._undo.push(() => {
      Module._load = originalLoad;
    });
    this._loaderInstalled = true;
  }

  // ------------------------------------------------------------------
  // Lifecycle
  // ------------------------------------------------------------------

  seal() {
    this._sealed = true;
    return this;
  }

  restore() {
    for (const undo of this._undo.reverse()) {
      try {
        undo();
      } catch {
        // Teardown is best effort.
      }
    }
    this._undo = [];
    this._bindings = [];
    this._caps.clear();
    this._originals.clear();
    this._proxies.clear();
    this._sealed = false;
    this._loaderInstalled = false;
  }

  // ------------------------------------------------------------------
  // Dispatch
  // ------------------------------------------------------------------

  _invoke(capId, thisArg, args) {
    const cap = this._caps.get(capId);
    if (!cap) {
      throw new CapabilityDenied(capId, 'unknown capability');
    }

    const decision = this._decide(cap, args);

    if (decision === Policy.ASK) {
      let approved = false;
      try {
        approved = Boolean(this._ask && this._ask(capId, args));
      } catch {
        approved = false;
      }
      this._emit(capId, approved ? 'ASK_ALLOW' : 'ASK_DENY', args);
      if (!approved) {
        throw new CapabilityDenied(capId, 'ask denied');
      }
      return Reflect.apply(this._originals.get(capId), thisArg, args);
    }

    this._emit(capId, decision, args);

    if (decision === Policy.ALLOW) {
      return Reflect.apply(this._originals.get(capId), thisArg, args);
    }
    if (decision === Policy.DENY) {
      throw new CapabilityDenied(capId);
    }
    if (decision === Policy.SUBSTITUTE) {
      const substitute = cap.substitute;
      return typeof substitute === 'function'
        ? Reflect.apply(substitute, thisArg, args)
        : substitute;
    }
    throw new CapabilityDenied(capId, `invalid decision: ${String(decision)}`);
  }

  _invokeConstruct(capId, args, newTarget) {
    const cap = this._caps.get(capId);
    if (!cap) {
      throw new CapabilityDenied(capId, 'unknown capability');
    }

    const decision = this._decide(cap, args);

    if (decision === Policy.ASK) {
      let approved = false;
      try {
        approved = Boolean(this._ask && this._ask(capId, args));
      } catch {
        approved = false;
      }
      this._emit(capId, approved ? 'ASK_ALLOW' : 'ASK_DENY', args);
      if (!approved) {
        throw new CapabilityDenied(capId, 'ask denied');
      }
      return Reflect.construct(this._originals.get(capId), args, newTarget);
    }

    this._emit(capId, decision, args);

    if (decision === Policy.ALLOW) {
      return Reflect.construct(this._originals.get(capId), args, newTarget);
    }
    if (decision === Policy.DENY) {
      throw new CapabilityDenied(capId);
    }
    if (decision === Policy.SUBSTITUTE) {
      const substitute = cap.substitute;
      if (typeof substitute === 'function') {
        return Reflect.construct(substitute, args, newTarget);
      }
      return substitute;
    }
    throw new CapabilityDenied(capId, `invalid decision: ${String(decision)}`);
  }

  _decide(cap, args) {
    const policy = cap.policy;
    if (typeof policy === 'function') {
      let decision;
      try {
        decision = policy(cap, args);
      } catch {
        throw new CapabilityDenied(cap.id, 'policy error');
      }
      if (
        decision === Policy.ALLOW ||
        decision === Policy.DENY ||
        decision === Policy.ASK ||
        decision === Policy.SUBSTITUTE
      ) {
        return decision;
      }
      throw new CapabilityDenied(cap.id, `invalid policy: ${String(decision)}`);
    }
    if (
      policy === Policy.ALLOW ||
      policy === Policy.DENY ||
      policy === Policy.ASK ||
      policy === Policy.SUBSTITUTE
    ) {
      return policy;
    }
    throw new CapabilityDenied(cap.id, `invalid policy: ${String(policy)}`);
  }

  _emit(capId, decision, args) {
    if (!this._audit) {
      return;
    }
    try {
      // Do not include argument values: String(args) can run guest code.
      this._audit({ cap: capId, decision, argc: args.length });
    } catch {
      // Auditing must never change the call's behavior.
    }
  }

  // ------------------------------------------------------------------
  // Introspection for the demo
  // ------------------------------------------------------------------

  describe() {
    return this._bindings.map((binding) => ({
      cap: binding.capId,
      description: binding.description,
    }));
  }
}

module.exports = {
  Interposer,
  Policy,
  CapabilityDenied,
};
