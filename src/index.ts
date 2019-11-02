import { sync as uid } from 'uid-safe'

import { IncomingMessage, ServerResponse } from 'http'
import { EventEmitter } from 'events'
import { Store as ExpressStore } from 'express-session';
import cookie, { CookieSerializeOptions } from 'cookie'
import url from 'url';
import onHeaders from 'on-headers'
import signature from 'cookie-signature'
import crypto from 'crypto'
import { Server } from 'https';

function generateSessionId(): string {
  return uid(24)
}

interface SessionOptions {
  genid?: any
  name?: string
  key?: string
  store?: MicroStore
  resave?: boolean
  rolling?: boolean
  saveUninitialized?: boolean
  secret: string | string[]
  unset?: string
  cookie?: Express.SessionCookieData
}

class MicroCookie implements Express.SessionCookie {
  _expires: Date | boolean = false
  originalMaxAge: number
  secure: boolean = false
  httpOnly: boolean = true
  path: string = '/'
  domain?: string
  sameSite: boolean | 'lax' | 'strict' | 'none' | undefined

  constructor(options?: Express.SessionCookieData) {
    let opts: any = options || {}

    this.expires = opts.expires || false
    this.path = opts.path || '/'
    this.maxAge = opts.maxAge
    this.originalMaxAge = opts.originalMaxAge === undefined ? opts.maxAge || 0: opts.originalMaxAge
    this.domain = opts.domain
    this.sameSite = opts.sameSite as 'lax' | 'strict' | 'none'
  }

  set expires(to: Date | boolean) {
    this._expires = to
    if (this.maxAge) {
      this.originalMaxAge = this.maxAge
    }
  }

  get expires(): Date | boolean {
    return this._expires
  }

  set maxAge(ms: number | null) {
    this.expires = ms ? new Date(Date.now() + ms): false
  }

  get maxAge(): number | null {
    return this.expires instanceof Date ? this.expires.valueOf() - Date.now() : null
  }

  get data() {
    return {
      originalMaxAge: this.originalMaxAge,
      expires: this._expires instanceof Date ? this._expires : undefined,
      secure: this.secure,
      httpOnly: this.httpOnly,
      domain: this.domain,
      path: this.path,
      sameSite: this.sameSite
    }
  }

  serialize(name: string, val: string): string {
    return cookie.serialize(name, val, this.data)
  }
}

function hash(sess: any): string {
  // serialize
  var str = JSON.stringify(sess, function (key, val) {
    // ignore sess.cookie property
    if (key === 'cookie' || key == 'store') {
      return
    }

    return val
  })

  // hash
  return crypto
    .createHash('sha1')
    .update(str, 'utf8')
    .digest('hex')
}

class MicroSession implements Express.Session {
  id: string
  req: any
  store: MicroStore
  cookie: MicroCookie
  [key: string]: any

  constructor(req: any, sessionData: any) {
    Object.defineProperty(this, 'req', {
      value: req
    })
    this.id = ''
    Object.defineProperty(this, 'id', {
      value: req.sessionID
    })

    this.store = req.sessionStore
    this.cookie = sessionData.cookie

    if (typeof sessionData == 'object') {
      for (var prop in sessionData) {
        if (!(prop in this)) {
          this[prop] = sessionData[prop]
        }
      }
    }
  }

  resetMaxAge(): this {
    this.cookie.maxAge = this.cookie.originalMaxAge
    return this
  }

  touch(): this {
    this.resetMaxAge()
    return this
  }

  private data(): { [key: string]: any } {
    let out: { [key: string]: any } = {}
    for (var prop in this) {
      if (prop === 'cookie' || prop === 'store') {
        continue
      }
      out[prop] = this[prop]
    }
    return out
  }

  save(cb?: (err?: any) => void): this {
    this.store.set(this.id, this.data(), cb || function() {})
    return this
  }

  reload(cb?: (err?: any) => void): this {
    this.store.get(this.id, (err, sess) => {
      if (err) return cb && cb(err)
      if (!sess) return cb && cb(new Error("failed to load session"))
      this.store.createSession(this.req, sess)
      cb && cb(null)
    })
    return this
  }

  destroy(cb?: (err?: any) => void): this {
    this.store.destroy(this.id, cb)
    return this
  }

  regenerate(cb: (err?: any) => void): this {
    this.store.regenerate(this.req, cb)
    return this
  }
}

abstract class MicroStore extends EventEmitter {
  constructor() {
    super()
  }

  public abstract destroy(id: string, cb?: (err?: any) => void): void;
  public abstract get(id: string, cb: (err?: any, session?: any) => void): void;
  public abstract set(id: string, session: any, cb?: (err?: any) => void): void;
  public abstract touch(id: string, session: any, cb?: (err?: any) => void): void;

  generate?: (req: ReqAndSessionInfo) => void

  regenerate(req: any, cb?: (err?: any) => void) {
    let id = req.sessionID
    this.destroy(id, (err) => {
      this.generate && this.generate(req)
      cb && cb(err)
    })
  }

  load(id: string, cb: (err: any, session?: Express.SessionData | null) => any) {
    this.get(id, (err, session) => {
      if (err) return cb(err)
      if (!session) return cb(null)
      let req = {
        sessionID: id,
        sessionStore: this
      }

      cb(null, this.createSession(req, session))
    })
  }

  createSession(req: any, session: any) {
    let expires = session.cookie && session.cookie.expires
    let originalMaxAge = session.cookie && session.cookie.originalMaxAge

    session.cookie = new MicroCookie(session.cookie)

    if (typeof expires == 'string') {
      session.cookie.expires = new Date(expires)
    }

    session.cookie.originalMaxAge = originalMaxAge

    req.session = new MicroSession({
      sessionStore: this,
      sessionID: session.id
    }, session)

    return req.session
  }
}

class MicroMemoryStore extends MicroStore implements ExpressStore {
  private sessions: { [id: string]: string } = {}


  constructor() {
    super()
  }

  all(cb: (err?: any, sessions?: { [id: string]: any }) => void) {
    let sessionIds = Object.keys(this.sessions)
    let sessions: { [id: string]: any } = {}

    for (let id of sessionIds) {
      let session = this.getSession(id)
      if (session) {
        sessions[id] = session
      }
    }

    cb && setImmediate(() => cb(null, sessions))
  }

  clear(cb?: (err?: any) => void) {
    this.sessions = {}
    cb && setImmediate(() => cb(null))
  }

  destroy(id: string, cb?: (err?: any) => void) {
    delete this.sessions[id]
    cb && setImmediate(() => cb(null))
  }

  get(id: string, cb: (err?: any, session?: any) => void) {
    let session = this.getSession(id)
    setImmediate(() => cb(null, session))
  }

  set(id: string, session: any, cb?: (err?: any) => void) {
    this.sessions[id] = JSON.stringify(session)
    cb && setImmediate(() => cb(null))
  }

  length(cb: (err?: any, length?: number) => void) {
    this.all((err, sessions) => {
      if (err) return cb(err)
      if (!sessions) return cb(null, 0)
      cb(null, Object.keys(sessions).length)
    })
  }

  touch(id: string, session: any, cb?: (err?: any) => void) {
    let currentSession = this.getSession(id)

    if (currentSession) {
      currentSession.cookie = session.cookie
      this.sessions[session] = JSON.stringify(currentSession)
    }

    cb && setImmediate(() => cb(null))
  }

  getSession(id: string): any {
    let sess = this.sessions[id]

    if (!sess) {
      return
    }

    let sessJSON = JSON.parse(sess)

    if (sessJSON.cookie) {
      let expires: Date
      if (!(sessJSON.cookie.expires instanceof Date)) {
        expires = new Date(sessJSON.cookie.expires)
      } else {
        expires = sessJSON.cookie.expires
      }

      if (expires && expires <= new Date(Date.now())) {
        delete this.sessions[id]
        return
      }
    }

    return sessJSON
  }
}

function unsigncookie(val: string, secrets: string[]) {
  for (var i = 0; i < secrets.length; i++) {
    var result = signature.unsign(val, secrets[i]);

    if (result !== false) {
      return result;
    }
  }

  return false;
}

function setcookie(res: ServerResponse, name: string, val: string, secret: string, options: CookieSerializeOptions) {
  var signed = 's:' + signature.sign(val, secret);
  var data = cookie.serialize(name, signed, options);

  var prev = res.getHeader('Set-Cookie') as string[] || []
  var header = Array.isArray(prev) ? prev.concat(data) : [prev, data];

  res.setHeader('Set-Cookie', header)
}

function getcookie(req: IncomingMessage, name: string, secrets: string[]) {
  var header = req.headers.cookie;
  var raw;
  var val;

  // read from cookie header
  if (header) {
    var cookies = cookie.parse(header);

    raw = cookies[name];

    if (raw) {
      if (raw.substr(0, 2) === 's:') {
        val = unsigncookie(raw.slice(2), secrets);

        if (val === false) {
          val = undefined;
        }
      }
    }
  }

  return val;
}

interface ReqAndSessionInfo extends IncomingMessage {
  sessionID: string
  session: MicroSession
  sessionStore: MicroStore
}

function SessionManager(options?: SessionOptions): (req: IncomingMessage, res: ServerResponse) => Promise<MicroSession> {
  let opts: SessionOptions = options || {} as SessionOptions

  let generateId = opts.genid || generateSessionId

  let name = opts.name || opts.key || 'micro.sid'

  let store = opts.store || new MicroMemoryStore()

  let resaveSession = opts.resave

  if (resaveSession === undefined) {
    resaveSession = true
  }

  let rolling = opts.rolling

  let cookieOptions = opts.cookie

  let saveUninitialized = opts.saveUninitialized

  if (saveUninitialized === undefined) {
    saveUninitialized = true
  }

  if (opts.unset && opts.unset !== 'destroy' && opts.unset !== 'keep') {
    throw new TypeError('unset option must be either destroy or keep')
  }

  let secret: string[]
  if (typeof opts.secret === 'string') {
    secret = [opts.secret]
  } else {
    secret = opts.secret
  }

  if (!secret) {
    throw new TypeError('session requires options.secret')
  }

  if (process.env.NODE_ENV === 'production' && opts.store instanceof MicroMemoryStore) {
    console.warn("MemoryStore should not be used in production")
  }

  let storeReady = true;

  store.on('disconnect', () => storeReady = false)
  store.on('connect', () => storeReady = false);

  store.generate = function (req: ReqAndSessionInfo) {
    req.sessionID = generateId(req);
    req.sessionStore = store
    req.session = new MicroSession(req, {});
    req.session.cookie = new MicroCookie(cookieOptions);
  };

  var storeImplementsTouch = typeof store.touch === 'function'

  return (req: IncomingMessage, res: ServerResponse): Promise<MicroSession> => {
    return new Promise((resolve, reject) => {
      if (!storeReady) {
        resolve()
        return
      }

      // pathname mismatch
      var originalPath = url.parse(req.url as string).pathname || '/'
      if (cookieOptions && originalPath.indexOf(cookieOptions.path || '/') !== 0) return;

      let cookieId = getcookie(req, name, secret)

      var originalId: string
      var originalHash: string
      let savedHash: string
      let session: MicroSession | undefined = undefined
      let touched: boolean = false

      function isModified(session: MicroSession) {
        return originalId !== session.id || originalHash !== hash(session);
      }

      // check if session has been saved
      function isSaved(sess: MicroSession) {
        return originalId === sess.id && savedHash === hash(session);
      }

      function shouldSetCookie(sessionID?: string | true | undefined, session?: MicroSession) {
        // cannot set cookie without a session ID
        if (typeof sessionID !== 'string' || !session) {
          return false;
        }

        return cookieId !== sessionID
          ? saveUninitialized || isModified(session)
          : rolling || session.cookie.expires != null && isModified(session);
      }

      // determine if session should be saved to store
      function shouldSave(id?: string, session?: MicroSession) {
        // cannot set cookie without a session ID
        if (typeof id !== 'string' || !session) {
          return false;
        }

        return !saveUninitialized && cookieId !== id
          ? isModified(session)
          : !isSaved(session)
      }

      // determine if session should be touched
      function shouldTouch(id?: string, session?: MicroSession) {
        // cannot set cookie without a session ID
        if (typeof id !== 'string') {
          return false;
        }

        return cookieId === id && !shouldSave(id, session);
      }

        onHeaders(res, () => {
          if (session === undefined) {
            return
          }

          if (!shouldSetCookie(cookieId, session)) {
            return
          }

          if (!touched) {
            session.touch()
            touched = true
          }

          setcookie(res, name, cookieId as string, secret[0], session.cookie.data)
        })

        var _end = res.end
        var _write = res.write
        var ended = false

        res.end = function(chunk?: any, encoding?: any, cb?: () => void) {
          if (ended) {
            return false;
          }

          ended = true;

          var ret: any;
          var sync = true;

          function writeend() {
            if (sync) {
              ret = _end.call(res, chunk, encoding);
              sync = false;
              return;
            }

            _end.call(res, null, "");
          }

          function writetop() {
            if (!sync) {
              return ret;
            }

            if (chunk == null) {
              ret = true;
              return ret;
            }

            var contentLength = Number(res.getHeader('Content-Length'));

            if (!isNaN(contentLength) && contentLength > 0) {
              // measure chunk
              chunk = !Buffer.isBuffer(chunk)
                ? Buffer.from(chunk, encoding)
                : chunk;
              encoding = undefined;

              if (chunk.length !== 0) {
                ret = _write.call(res, chunk.slice(0, chunk.length - 1), encoding);
                chunk = chunk.slice(chunk.length - 1, chunk.length);
                return ret;
              }
            }

            ret = _write.call(res, chunk, encoding);
            sync = false;

            return ret;
          }

          // no session to save
          if (!session) {
            return _end.call(res, chunk, encoding);
          }

          if (!touched) {
            // touch session
            session.touch()
            touched = true
          }

          if (shouldSave(cookieId as string, session)) {
            session.save(function onsave(err) {
              if (err) {
                setImmediate(reject, err)
                return
              }

              writeend();
            });

            return writetop();
          } else if (storeImplementsTouch && shouldTouch(cookieId as string, session)) {

            // store implements touch method
            store.touch(cookieId as string, session, function ontouch(err) {
              if (err) {
                setImmediate(reject, err);
              }

              writeend();
            });

            return writetop();
          }

          return _end.call(res, chunk, encoding);
        }

        // generate the session
      function generate() {
        let fakeReq: any = req;
        fakeReq.sessionID = cookieId;
        fakeReq.session = session;
        store.generate && store.generate(fakeReq);
        originalId = fakeReq.sessionID;
        originalHash = hash(fakeReq.session);
        session = fakeReq.session
        cookieId = fakeReq.sessionID
        wrapmethods(session as MicroSession);
      }

      // inflate the session
      function inflate (req: any, sess: MicroSession) {
        store.createSession(req as any, sess)
        originalId = req.sessionID
        originalHash = hash(sess)

        if (!resaveSession) {
          savedHash = originalHash
        }

        wrapmethods(req.session)

        session = req.session
      }

      // wrap session methods
      function wrapmethods(sess: MicroSession) {
        var _reload = sess.reload
        var _save = sess.save

        function reload(this: MicroSession, callback: Function) {
          _reload.call(this, function () {
            wrapmethods(session as MicroSession)
            callback(arguments)
          })
        }

        function save(this: MicroSession, cb?: (err?: any) => void) {
          savedHash = hash(this);
          _save.apply(this, [cb]);
        }

        Object.defineProperty(sess, 'reload', {
          configurable: true,
          enumerable: false,
          value: reload,
          writable: true
        })

        Object.defineProperty(sess, 'save', {
          configurable: true,
          enumerable: false,
          value: save,
          writable: true
        });
      }

      // generate a session if the browser doesn't send a sessionID
      if (!cookieId) {
        generate()
        resolve(session)
        return
      }

      // generate the session object
      store.get(cookieId as string, (err, sess) => {
        // error handling
        if (err && err.code !== 'ENOENT') {
          reject(err)
          return
        }

        try {
          if (err || !sess) {
            generate()
          } else {
            inflate(req, sess)
          }
        } catch (e) {
          reject(e)
          return
        }

        resolve(session)
      });
    })
  }
}

namespace SessionManager {
  export var Cookie: typeof MicroCookie = MicroCookie
  export var MemoryStore: typeof MicroMemoryStore = MicroMemoryStore
  export var Store: typeof MicroStore = MicroStore
  export var Session: typeof MicroSession = MicroSession
}

export = SessionManager
