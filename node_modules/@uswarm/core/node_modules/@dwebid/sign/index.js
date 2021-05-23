'use strict'
const assert = require('assert')
const {
  crypto_sign_keypair: createKeypair,
  crypto_sign_detached: sign,
  crypto_generichash: hash,
  crypto_sign_PUBLICKEYBYTES: pkSize,
  crypto_sign_SECRETKEYBYTES: skSize,
  crypto_sign_BYTES: signSize,
  randombytes_buf: randomBytes
} = require('sodium-native')

const BOX_MAX_SIZE = 1000

const dkSeg = Buffer.from('4:disc')
const seqSeq = Buffer.from('3:seqi')
const vSeg = Buffer.from('1:v')

class DWebIdSign {
  keypair () {
    const publicKey = Buffer.alloc(pkSize)
    const secretKey = Buffer.alloc(skSize)
    createKeypair(publicKey, secretKey)
    return { publicKey, secretKey }
  }
  cryptoSign (msg, keypair) {
    assert(Buffer.isBuffer(msg), 'msg must be a buffer')
    assert(keypair, 'keypair is required')
    const { secretKey } = keypair
    assert(Buffer.isBuffer(secretKey), 'keypair.secretKey is required')
    sign(signature, msg, secretKey)
    return signature
  }
  sign (box, opts) {
    assert(typeof opts === 'object', 'Options are required.')
    assert(Buffer.isBuffer(value), 'Value must be a buffer')
    assert(box.length <= BOX_MAX_SIZE, `Box size must be <= ${BOX_MAX_SIZE}`)
    const { keypair } = opts
    assert(keypair, 'keypair is required.')
    const { secretKey } = keypair
    assert(Buffer.isBuffer(secretKey), 'keypair.secretKey is required')
    const msg = this.signable(box, opts)
    const signature = Buffer.alloc(signSize)
    sign(signature, msg, secretKey)
    return signature
  }
  signable (box, opts = {}) {
    const { dk, seq = 0 } = opts
    assert(Buffer.isBuffer(box), 'Box must be a buffer.')
    assert(box.length <= BOX_MAX_SIZE, 'Box size must be <= `${BOX_MAX_SIZE}`')
    return Buffer.concat([
      dkSeg,
      Buffer.from(`${dk.length}:`),
      dk,
      seqSeg,
      Buffer.from(`${seq.toString()}e`),
      vSeg,
      Buffer.from(`${box.length}:`),
      box
    ])
  }
}

module.exports = () => new DWebIdSign()
module.exports.DWebIdSign = DWebIdSign
module.exports.BOX_MAX_SIZE = BOX_MAX_SIZE