'use strict'
const { DWebDHT } = require('@dswarm/dht')
const LRU = require('hashlru')
const { UserStore, RoomStore } = require('./stores')
const { MutableUser } = require('./mutable-stores')

module.exports = opts => new USwarm(opts)

class USwarm extends DWebDHT {
  constructor (opts) {
    if (!opts) opts = {}
    super(opts)

    const {
      maxAge = 12 * 60 * 1000,
      maxValues = 5000
    } = opts

    this._store = LRU(maxValues)
    this.user = new UserStore(this, this._store)
    this.room = new RoomStore(this, this._store)
    this.muser = new MutableUser(this, this._store)

    // Kademilia DHT custom commands
    this.command('user-store', this.user._command())
    this.command('room-store', this.room._command())
    this.command('mutable-user', this.muser._command())
  }

  getUser (username, cb) {
    return this.query('user-store', username, cb)
  }

  getRoom (roomName, cb) {
    return this.query('room-store', roomName, cb)
  }
}