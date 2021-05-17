const { EventEmitter } = require('events')
const maybe = require('call-me-maybe')
const inspect = require('inspect-custom-symbol')

const SUPPORTS_PROMISES = Symbol.for('ddatabase.promises')
const BASE = Symbol('ddatabase-promisifier.base')
const REQUEST = Symbol('ddatabase-promisifier.request')

class BaseWrapper extends EventEmitter {
  constructor (base) {
    super()
    this[BASE] = base
    this.on('newListener', (eventName, listener) => {
      base.on(eventName, listener)
    })
    this.on('removeListener', (eventName, listener) => {
      base.removeListener(eventName, listener)
    })
  }

  [inspect] (depth, opts) {
    return this[BASE][inspect](depth, opts)
  }

  get key () {
    return this[BASE].key
  }

  get discoveryKey () {
    return this[BASE].discoveryKey
  }

  get length () {
    return this[BASE].length
  }

  get byteLength () {
    return this[BASE].byteLength
  }

  get writable () {
    return this[BASE].writable
  }

  get sparse () {
    return this[BASE].sparse
  }

  get peers () {
    return this[BASE].peers
  }

  get valueEncoding () {
    return this[BASE].valueEncoding
  }

  get weak () {
    return this[BASE].weak
  }

  get lazy () {
    return this[BASE].lazy
  }
}

class CallbackToPromiseDDatabase extends BaseWrapper {
  constructor (base) {
    super(base)
    this[SUPPORTS_PROMISES] = true
  }

  // Async Methods

  ready () {
    return alwaysCatch(new Promise((resolve, reject) => {
      this[BASE].ready(err => {
        if (err) return reject(err)
        return resolve(null)
      })
    }))
  }

  close () {
    return alwaysCatch(new Promise((resolve, reject) => {
      this[BASE].close(err => {
        if (err) return reject(err)
        return resolve(null)
      })
    }))
  }

  get (index, opts) {
    let req = null
    const prom = new Promise((resolve, reject) => {
      req = this[BASE].get(index, opts, (err, block) => {
        if (err) return reject(err)
        return resolve(block)
      })
    })
    prom[REQUEST] = req
    return prom
  }

  append (batch) {
    return alwaysCatch(new Promise((resolve, reject) => {
      this[BASE].append(batch, (err, seq) => {
        if (err) return reject(err)
        return resolve(seq)
      })
    }))
  }

  update (opts) {
    return alwaysCatch(new Promise((resolve, reject) => {
      this[BASE].update(opts, err => {
        if (err) return reject(err)
        return resolve(null)
      })
    }))
  }

  seek (bytes, opts) {
    return new Promise((resolve, reject) => {
      this[BASE].seek(bytes, opts, (err, index, relativeOffset) => {
        if (err) return reject(err)
        return resolve([index, relativeOffset])
      })
    })
  }

  download (range) {
    let req = null
    const prom = alwaysCatch(new Promise((resolve, reject) => {
      req = this[BASE].download(range, err => {
        if (err) return reject(err)
        return resolve(null)
      })
    }))
    prom[REQUEST] = req
    return prom
  }

  has (start, end) {
    return new Promise((resolve, reject) => {
      this[BASE].has(start, end, (err, res) => {
        if (err) return reject(err)
        return resolve(res)
      })
    })
  }

  audit () {
    return new Promise((resolve, reject) => {
      this[BASE].audit((err, report) => {
        if (err) return reject(err)
        return resolve(report)
      })
    })
  }

  destroyStorage () {
    return new Promise((resolve, reject) => {
      this[BASE].destroyStorage(err => {
        if (err) return reject(err)
        return resolve(null)
      })
    })
  }

  // Sync Methods

  createReadStream (opts) {
    return this[BASE].createReadStream(opts)
  }

  createWriteStream (opts) {
    return this[BASE].createWriteStream(opts)
  }

  undownload (range) {
    return this[BASE].undownload(range[REQUEST] || range)
  }

  cancel (range) {
    return this[BASE].cancel(range[REQUEST] || range)
  }

  replicate (initiator, opts) {
    return this[BASE].replicate(initiator, opts)
  }

  registerExtension (name, handlers) {
    return this[BASE].registerExtension(name, handlers)
  }

  setUploading (uploading) {
    return this[BASE].setUploading(uploading)
  }

  setDownloading (downloading) {
    return this[BASE].setDownloading(downloading)
  }
}

class PromiseToCallbackDDatabase extends BaseWrapper {
  constructor (base) {
    super(base)
    this[SUPPORTS_PROMISES] = false
  }

  // Async Methods

  ready (cb) {
    return maybeOptional(cb, this[BASE].ready())
  }

  close (cb) {
    return maybeOptional(cb, this[BASE].close())
  }

  get (index, opts, cb) {
    const prom = this[BASE].get(index, opts)
    maybe(cb, prom)
    return prom
  }

  append (batch, cb) {
    return maybeOptional(cb, this[BASE].append(batch))
  }

  update (opts, cb) {
    return maybeOptional(cb, this[BASE].update(opts))
  }

  seek (bytes, opts, cb) {
    return maybe(cb, this[BASE].seek(bytes, opts))
  }

  download (range, cb) {
    const prom = this[BASE].download(range)
    maybeOptional(cb, prom)
    return prom
  }

  has (start, end, cb) {
    return maybe(cb, this[BASE].has(start, end))
  }

  audit (cb) {
    return maybe(cb, this[BASE].audit())
  }

  destroyStorage (cb) {
    return maybe(cb, this[BASE].destroyStorage())
  }

  // Sync Methods

  createReadStream (opts) {
    return this[BASE].createReadStream(opts)
  }

  createWriteStream (opts) {
    return this[BASE].createWriteStream(opts)
  }

  undownload (range) {
    return this[BASE].undownload(range)
  }

  cancel (range) {
    return this[BASE].cancel(range)
  }

  replicate (initiator, opts) {
    return this[BASE].replicate(initiator, opts)
  }

  registerExtension (name, handlers) {
    return this[BASE].registerExtension(name, handlers)
  }

  setUploading (uploading) {
    return this[BASE].setUploading(uploading)
  }

  setDownloading (downloading) {
    return this[BASE].setDownloading(downloading)
  }
}

module.exports = {
  toPromises,
  toCallbacks,
  unwrap
}

function toPromises (base) {
  return base[SUPPORTS_PROMISES] ? base : new CallbackToPromiseDDatabase(base)
}

function toCallbacks (base) {
  return base[SUPPORTS_PROMISES] ? new PromiseToCallbackDDatabase(base) : base
}

function unwrap (base) {
  return base[BASE] || base
}

function maybeOptional (cb, prom) {
  prom = maybe(cb, prom)
  if (prom) prom.catch(noop)
  return prom
}

function alwaysCatch (prom) {
  prom.catch(noop)
  return prom
}

function noop () {}
