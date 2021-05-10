'use strict'
const { DWebDHT } = require('@dswarm/dht')
const LRU = require('hashlru')
const { UserStore, RoomStore } = require('./stores')

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
    
    this.command('user-store', this.user._command())
    this.command('room-store', this.room._command())
  }

  
}
