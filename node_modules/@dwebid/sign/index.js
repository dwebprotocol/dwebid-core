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

const VALUE_MAX_SIZE = 1000
const dkSeg = Buffer.from('4:didk')
const seqSeg = Buffer.from('3:seqi')
const vSeg = Buffer.from('1:v')

class DWebIdSign {
  keypair () {
    const publicKey = Buffer.alloc(pkSize)
    const secretKey = Buffer.alloc(skSize)
    createKeypair(publicKey, secretKey)
    return { publicKey, secretKey }
  }

  cryptoSign (msg, keypair) {
    assert(Buffer.isBuffer(msg), 'msg must be a Buffer.')
    assert(keypair, 'keypair is required')
    const { secretKey } = keypair
    assert(Buffer.isBuffer(secretKey), 'keypair.secretKey is required.')
    const signature = Buffer.alloc(signSize)
    sign(signature, msg, secretKey)
    return signature
  }
  sign (username, opts) {
    assert(typeof opts === 'object', 'Options are required')
    assert(Buffer.isBuffer(username), 'Username must be a buffer')
    assert(username.length <= VALUE_MAX_SIZE, `Username size must be <= ${VALUE_MAX_SIZE}`) 
    assert(opts.dk, 'Options must include the identity document key')
    const { keypair } = opts
    assert(keypair, 'keypair is required')
    const { secretKey } = keypair
    assert(Buffer.isBuffer(secretKey), 'keypair.secretKey is required.')
    const msg = this.signable(username, opts)
    const signature = Buffer.alloc(signSize)
    sign(signature, msg, secretKey)
    return signature  
  }
  signable (username, opts = {}) {
    const { dk, seq = 0 } = opts
    assert(Buffer.isBuffer(value), 'Username must be a buffer.')
    assert(username.length <= VALUE_MAX_SIZE, `Username size must be <= ${VALUE_MAX_SIZE}`)
    assert(dk, 'opts must include the identity document key')
    return Buffer.concat([
      dkSeg,
      Buffer.from(`${dk.length}:`),
      dk,
      seqSeq,
      Buffer.from(`${seq.toString()}e`),
      vSeg,
      Buffer.from(`${username.length}:`),
      username
    ])
  }
}

module.exports = () => new DWebIdSign()
module.exports.DWebIdSign = DWebIdSign
module.exports.VALUE_MAX_SIZE = VALUE_MAX_SIZE