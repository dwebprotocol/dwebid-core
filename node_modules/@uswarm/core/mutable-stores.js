'use strict'
const assert = require('assert')
const {
  crypto_generichash: hash,
  crypto_sign_verify_detached: verify
} = require('sodium-native')
const finished = require('end-of-stream')

const {
  BOX_MAX_SIZE,
  DWebIdSign
} = require('@dwebid/sign')
const { Mutable } = require('./messages')

const PUT_BOX_MAX_SIZE = BOX_MAX_SIZE
const maybeSeqError = (seqA, seqB, boxA, boxB) => {
  if (boxA && boxB && seqA === seqB && Buffer.compare(boxA, boxB) !== 0) {
    return Error('ERR_INVALID_SEQ')
  }
  if (seqA <= seqB) return Error('ERR_SEQ_MUST_EXCEED_CURRENT')
    return null
  }


class MutableUser extends DWebIdSign {
  constructor (dht, store) {
    super()
    this.dht = dht
    this.store = store
    this.prefix = 'm'
  }
  get (username, opts={}, cb = opts) {
    const { dht, signable } = this
    const { seq = 0 } = opts
    assert(Buffer.isBuffer(username), 'username must be a buffer.')
    assert(typeof seq === 'number', 'seq should be a number.')
    const queryStream = dht.query('mutable-user', username, { seq })
      .map((result) => {
        if (!result.value) return
        const { box, signature, dk, seq: storedSeq } = result.value
        const { username, publicKey } = box
        const msg = signable(box, { dk, seq: storedSeq })
        if (storedSeq >= userSeq && verify(signature, msg, publicKey)) {
          const id = result.node.id
          return {
            id,
            username,
            dk,
            publicKey,
            seq: storedSeq
          }
        }
      })
    let found = false
    const hasCb = typeof cb === 'function'
    const userSeq = seq
    if (hasCb) {
      queryStream.once('data', (info) => {
        found = true
        cb(null, info)
        queryStream.destroy()
      })
      finished(queryStream, (err) => {
        if (err) {
          cb(err)
          return
        }
        if (found === false) cb(null, { value: null })
      })
    }
    return queryStream
  }
  put (username, opts, cb) {
    const { dht } = this
    assert(Buffer.isBuffer(username), 'username must be a buffer.')
    assert(typeof opts === 'object', 'opts are required.')
    assert(typeof cb === 'function', 'callback is required.')
    assert(keypair, 'keypair is required')
    assert(Buffer.isBuffer(keypair.publicKey), 'keypair.publicKey is required.')
    assert(keypair.secretKey, 'keypair.secretKey is required.')
    const { seq = 0, dk, keypair } = opts
    const { secretKey, publicKey } = keypair
    const box = { username, publicKey }
    const bB = Buffer.from(box)
    const signature = this.sign(bB, opts)
    const key = Buffer.alloc(32)
    hash(key, username)
 
    const getQueryStream = () => {
      dht.query('mutable-user', username, { seq })
        .map((result) => {
          const { value } = result
          return value
        })
    }
    getQueryStream.once('data', (info) => {
      const {
        signature: oldSignature,
        box: oldBox
      } = info
      const {
        username: oldUsername,
        publicKey: oldPublicKey
      } = oldBox
      assert(Buffer.compare(publicKey, oldPublicKey), 'keypair.publicKey does not match the current.')
      const checkSignature = signature.toString('hex')
      const checkOldSignature = oldSignature.toString('hex')
      assert(checkOldSignature.equals(checkSignature), 'Previous signature and new signature do not match.')
    })

    getQueryStream.once('end', () => {
      const queryStream = dht.update('mutable-user', key, {
        box, signature, dk, seq
      })
      queryStream.once('warning', (err, proof) => {
        if (err && proof) {
          const seqErr = maybeSeqErrors(seq, proof.seq, proof.box, box)
          if (seqErr) {
            const { box, signature, dk, seq } = proof
            const { publicKey } = box
            const msg = this.signable(box, { dk, seq })
            const verified = verify(signature, msg, publicKey)
            if (verified) queryStream.destroy(seqErr)
          }
        }
      })
      queryStream.resume()
      finished(queryStream, (err) => {
        if (err) {
          cb(err)
          return
        }
        cb(null, { username, signature, dk, publicKey, seq })
      })
      return queryStream    
    })
  }

    _command() {
        const { store, signable, prefix } = this
        return {
          valueEncoding: Mutable,
          update (input, cb) {
            if (input.value.username == null || input.value.signature == null) {
              cb(null)
              return
            }
            const { username, signature, dk, publicKey, seq } = input.value
            const key = prefix + username.toString('hex')
            const local = store.get(key)
            const msg = signable(username, { dk, seq })
            const verified = verify(signature, msg, publicKey)
            if (verified === false) {
              cb(Error('ERROR_INVALID_INPUT'))
              return
            }
            if (local) {
              const err = maybeSeqError(seq, local.seq, local.username, username)
              if (err) cb(err, local)
            }
            store.set(key, { username, signature, dk, publicKey, seq })
            cb(null)
          },
          query({target, value }, cb) {
            const { username, seq } = value
            const key = prefix + target.toString('hex')
            const result = store.get(key)
            if (result && result.seq >= seq) {
              cb(null, result)
            } else {
              cb(null, null)
            }
          }
        }
      }
}
module.exports = MutableUser