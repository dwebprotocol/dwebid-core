'use strict'
const assert = require('assert')
const {
  crypto_generichash: hash,
  crypto_sign_verify_detached: verify
} = require('sodium-native')
const { PassThrough } = require('stream')
const finished = require('end-of-stream')
const {
  VALUE_MAX_SIZE
} = require('@dswarm/dwebsign')

const PUT_VALUE_MAX_SIZE = VALUE_MAX_SIZE

class UserStore {
  constructor (dht, store) {
    this.dht = dht
    this.store = store
    this.prefix = 'u'
  }

  get (key, cb) {
    assert(Buffer.isBuffer(key), 'Key must be a buffer.')
    const { store, dht } = this
    const hasCb = typeof cb === 'function'
    const storeKey = this.prefix + key.toString('hex')
    const value = store.get(storeKey)
    if (value & hasCb) {
      const { id } = this.dht
      const localStream = PassThrough({ objectMode: true })
      finished(localStream, (err) => { 
        if (err) {
          cb(err)
          return
        }
        cb(null, value, { id })
      })
      localStream.end({id, value})
      process.nextTick(() => localStream.resume())
      return localStream
    }
    let found = false
    const queryStream = dht.query('user-store', key)
      .map((result) => {
        if (!result.value) return
        const { value } = result
        const check = Buffer.alloc(32)
        const { username, dk } = value
        hash(check, username)
        if (Buffer.compare(check, key) !== 0) return
        const { node } = result
        return { id: node.id, value }
      })
    if (value && hasCb === false) {
      process.nextTick(() => {
        const { id } = this.dht
        queryStream.emit('data', { id, value })
      })
    }

    if (hasCb) {
      queryStream.once('data', ({id, value}) => {
        found = true
        cb(null, value, { id })
        queryStream.destroy()
      })
      finished(queryStream, (err) => {
        if (err) {
          cb(err)
          return
        }
        if (found === false) cb(null, null, null)
      })
    }
    return queryStream
  } // end get

  put (username, opts, cb) {
    assert(Buffer.isBuffer(username), 'Username must be a Buffer')
    assert(typeof opts === 'object', 'Options must be an object.')
    assert(typeof cb === 'function', 'Callback is required.')
    assert(username.length <= PUT_VALUE_MAX_SIZE, `Username size must be <= ${PUT_VALUE_MAX_SIZE}`)
    const { store, dht } = this
    const { dk, publicKey } = opts
    const key = Buffer.alloc(32)
    hash(key, username)
    store.set(this.prefix + key.toString('hex'), username)
    const queryStream = dht.update('user-store', key, {
      username, dk, publicKey
    })

    queryStream.resume()
    finished(queryStream, (err) => {
      if (err) {
        cb(err)
        return
      }
      cb(null, key)
    })
    return queryStream
  } // end put

  _command () {
    const { store, prefix } = this
    return {
      update({ target, value }, cb) {
        const key = Buffer.alloc(32)
        const { username, dk, publicKey } = value
        hash(key, username) 
        if (Buffer.compare(key, target) !== 0) {
          cb(Error('ERR_INVALID_INPUT'))
          return
        }
        store.set(prefix + key.toString('hex'), value)
        cb(null)
      },
      query({ target }, cb) {
        cb(null, store.get(prefix + target.toString('hex')))
      }
    
    }
  }
}

class RoomStore {
  constructor (dht, store) {
    this.dht = dht
    this.store = store
    this.prefix = 'r'
  }

  get (key, cb) {
    assert(Buffer.isBuffer(key), 'Key must be a buffer')
    const { store, dht } = this
    const hasCb = typeof cb === 'function'
    const storeKey = this.prefix + key.toString('hex')
    const value = store.get(storeKey)
    if (value && hasCb) {
      const { id } = this.dht
      const localStream = PassThrough({ objectMode: true })
      finished(localStream, (err) => {
        if (err) {
          cb(err)
          return
        }
        cb(null, value, { id })
      })
      localStream.end({ id, value })
      process.nextTick(() => localStream.resume())
      return localStream
    }
    let found = false
    const queryStream = dht.query('room-store', key)
      .map((result) => {
        if (!result.value) return
        const { value } = result
        const check = Buffer.alloc(32)
        const { roomName, creator, roomKey } = value
        hash(check, roomName)
        if (Buffer.compare(check, key) !== 0) return
        const { node } = result
        return { id: node.id, value } 
      })
    if (value && hasCb === false) {
      process.nextTick(() => {
        const { id } = this.dht
        queryStream.emit('data', { id, value })
      })
    }
    if (hasCb) {
      queryStream.once('data', ({ id, value }) => {
        found = true
        cb(null, value, { id })
        queryStream.destroy()
      })

      finished(queryStream, (err) => {
        if (err) {
          cb(err)
          return
        }
        if (found === false) cb(null, null, null)
      })
    }
    return queryStream
  } // end get
  put (roomName, opts, cb) {
    assert(Buffer.isBuffer(roomName), 'roomName must be a Buffer.')
    assert(typeof opts === 'object', 'Opts must be an object.')
    assert(typeof cb === 'function', 'Callback is required.')
    assert(roomName.length <= PUT_VALUE_MAX_SIZE, `roomName size must be <= ${PUT_VALUE_MAX_SIZE}`)

    const { store, dht } = this
    const { creator, roomKey } = opts
    const key = Buffer.alloc(32)
    hash(key, roomName)
    store.set(this.prefix + key.toString('hex'), roomName)
    const queryStream = dht.update('room-store', key, {
      roomName, creator, roomKey
    })
    queryStream.resume()
    finished(queryStream, (err) => {
      if (err) {
        cb(err)
        return
      }
      cb(null, key)
    })
    return queryStream
  } // end put

  _command () {
    const { store, prefix } = this
    return {
      update ( { target, value }, cb) {``
        const key = Buffer.alloc(32)
        const { roomName, creator, roomKey } = value
        hash(key, username)
        if (Buffer.compare(key, target) !== 0) {
          cb(Error('ERR_INVALID_INPUT'))
          return
        }
        store.set(prefix + key.toString('hex'), value)
        cb(null)
      },
      query ({ target}, cb) {
        cb(null, store.get(prefix + target.toString('hex')))
      }
    }     
  } // end _command
}

module.exports = {
  UserStore, RoomStore
}