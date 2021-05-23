'use strict'
const { test } = require('tap')
const {
  crypto_sign_verify_detached: verify,
  crypto_generichash: hash
} = require('sodium-universal')
const dwebsign = require('../')()
const bencode = require('bencode')
test('keypair', async ({ is }) => {
  const { publicKey, secretKey } = dwebsign.keypair()
  is(publicKey instanceof Buffer, true)
  is(publicKey.length, 32)
  is(secretKey instanceof Buffer, true)
  is(secretKey.length, 64)
})

test('salt', async ({ is, throws }) => {
  const salt = dwebsign.salt()
  is(salt instanceof Buffer, true)
  is(salt.length, 32)
  is(dwebsign.salt(64).length, 64)
  throws(() => dwebsign.salt(15))
  throws(() => dwebsign.salt(65))
})

test('salt string', async ({ is, throws }) => {
  const salt = dwebsign.salt('test')
  is(salt instanceof Buffer, true)
  is(salt.length, 32)
  is(dwebsign.salt(64).length, 64)
  const check = Buffer.alloc(32)
  hash(check, Buffer.from('test'))
  is(salt.equals(check), true)
  throws(() => dwebsign.salt('test', 15))
  throws(() => dwebsign.salt('test', 65))
})

test('signable', async ({ is, same }) => {
  const salt = dwebsign.salt()
  const value = Buffer.from('test')
  same(
    dwebsign.signable(value),
    bencode.encode({ seq: 0, v: value }).slice(1, -1)
  )
  same(
    dwebsign.signable(value, { seq: 1 }),
    bencode.encode({ seq: 1, v: value }).slice(1, -1)
  )
  same(
    dwebsign.signable(value, { salt }),
    bencode.encode({ salt, seq: 0, v: value }).slice(1, -1)
  )
})

test('signable - decodable with bencode', async ({ is, same }) => {
  const salt = dwebsign.salt()
  const value = Buffer.from('test')
  const msg = dwebsign.signable(value, { salt })
  const result = bencode.decode(
    Buffer.concat([Buffer.from('d'), msg, Buffer.from('e')])
  )
  is(Buffer.isBuffer(result.salt), true)
  is(Buffer.isBuffer(result.v), true)
  same(result.salt, salt)
  same(result.v, value)
  is(result.seq, 0)
})

test('signable - salt must be a buffer', async ({ throws }) => {
  throws(() => dwebsign.signable(Buffer.from('test'), { salt: 'no' }), 'salt must be a buffer')
})

test('signable - salt size must be no greater than 64 bytes', async ({ throws }) => {
  throws(
    () => dwebsign.signable(Buffer.from('test'), { salt: Buffer.alloc(65) }),
    'salt size must be no greater than 64 bytes'
  )
})

test('signable - value must be buffer', async ({ throws }) => {
  const keypair = dwebsign.keypair()
  throws(() => dwebsign.signable('test', { keypair }), 'Value must be a buffer')
})

test('signable - value size must be <= 1000 bytes', async ({ throws }) => {
  const keypair = dwebsign.keypair()
  throws(
    () => dwebsign.signable(Buffer.alloc(1001), { keypair }),
    'Value size must be <= 1000'
  )
})

test('sign', async ({ is }) => {
  const keypair = dwebsign.keypair()
  const { publicKey } = keypair
  const salt = dwebsign.salt()
  const value = Buffer.from('test')
  is(
    verify(
      dwebsign.sign(value, { keypair }),
      dwebsign.signable(value),
      publicKey
    ),
    true
  )
  is(
    verify(
      dwebsign.sign(value, { salt, keypair }),
      dwebsign.signable(value, { salt }),
      publicKey
    ),
    true
  )
  is(
    verify(
      dwebsign.sign(value, { seq: 2, keypair }),
      dwebsign.signable(value, { seq: 2 }),
      publicKey
    ),
    true
  )
})

test('sign - salt must be a buffer', async ({ throws }) => {
  throws(() => dwebsign.sign(Buffer.from('test'), { salt: 'no' }), 'salt must be a buffer')
})

test('sign - salt size must be >= 16 bytes and <= 64 bytes', async ({ throws }) => {
  throws(
    () => dwebsign.sign(Buffer.from('test'), { salt: Buffer.alloc(15) }),
    'salt size must be between 16 and 64 bytes (inclusive)'
  )
  throws(
    () => dwebsign.sign(Buffer.from('test'), { salt: Buffer.alloc(65) }),
    'salt size must be between 16 and 64 bytes (inclusive)'
  )
})

test('sign - value must be buffer', async ({ throws }) => {
  const keypair = dwebsign.keypair()
  throws(() => dwebsign.sign('test', { keypair }), 'Value must be a buffer')
})

test('sign - options are required', async ({ throws }) => {
  throws(() => dwebsign.sign('test'), 'Options are required')
})

test('sign - value size must be <= 1000 bytes', async ({ throws }) => {
  const keypair = dwebsign.keypair()
  throws(
    () => dwebsign.sign(Buffer.alloc(1001), { keypair }),
    'Value size must be <= 1000'
  )
})

test('sign - keypair option is required', async ({ throws }) => {
  throws(
    () => dwebsign.sign(Buffer.alloc(1001), {}),
    'keypair is required'
  )
})

test('sign - keypair must have secretKey which must be a buffer', async ({ throws }) => {
  const keypair = dwebsign.keypair()
  keypair.secretKey = 'nope'
  throws(
    () => dwebsign.sign(Buffer.alloc(1001), { keypair }),
    'keypair.secretKey is required'
  )
  delete keypair.secretKey
  throws(
    () => dwebsign.sign(Buffer.alloc(1001), { keypair }),
    'keypair.secretKey is required'
  )
})

test('cryptoSign - msg must be buffer', async ({ throws }) => {
  const keypair = dwebsign.keypair()
  throws(() => dwebsign.cryptoSign('test', keypair), 'msg must be a buffer')
})

test('cryptoSign - keypair is required', async ({ throws }) => {
  throws(() => dwebsign.cryptoSign('test'), 'keypair is required')
})

test('cryptoSign - keypair must have secretKey which must be a buffer', async ({ throws }) => {
  const keypair = dwebsign.keypair()
  keypair.secretKey = 'nope'
  throws(
    () => dwebsign.cryptoSign(Buffer.alloc(1001), { keypair }),
    'keypair.secretKey is required'
  )
  delete keypair.secretKey
  throws(
    () => dwebsign.cryptoSign(Buffer.alloc(1001), { keypair }),
    'keypair.secretKey is required'
  )
})

test('cryptoSign', async ({ is }) => {
  const keypair = dwebsign.keypair()
  const { publicKey } = keypair
  const salt = dwebsign.salt()
  const value = Buffer.from('test')
  is(
    verify(
      dwebsign.cryptoSign(dwebsign.signable(value), keypair),
      dwebsign.signable(value),
      publicKey
    ),
    true
  )
  is(
    verify(
      dwebsign.cryptoSign(dwebsign.signable(value, { salt }), keypair),
      dwebsign.signable(value, { salt }),
      publicKey
    ),
    true
  )
  is(
    verify(
      dwebsign.cryptoSign(dwebsign.signable(value, { seq: 2 }), keypair),
      dwebsign.signable(value, { seq: 2 }),
      publicKey
    ),
    true
  )
})
