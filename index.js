import os from 'os'
import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import assert from 'assert'
import { NanoresourcePromise, Nanoresource } from 'nanoresource-promise/emitter'
import { USwarm } from '@uswarm/core'
import dswarm from 'dswarm'
import pump from 'pump'

export default class DWebIdentity extends Nanoresource {
  constructor (opts = {}) {
    super()
    this.dhtOpts = opts.dhtOpts || null
    this.seq = opts.seq || 0
    this.homeDir = opts.homeDir || os.homeDir()
    this.idDir = path.join(this.homeDir, opts.idDir || 'identities')
    this.user = opts.user
    this.userIdDir = path(this.idDir, this.user)
    this.iddb = null
    this.dht = null
    this.key = opts.key || null
    this.dk = crypto.createHash('sha256'.update(`${this.user}`).digest())
    this.secretKey = null
    this.currentKeypair = opts.currentKeypair || null
    this.keypair = null
    this.deviceDir = path.join(this.userIdDir, opts.deviceDir || 'devices')
    this.isReady = false
    this.isMaster = false
    this.localSlaveKey = null
  }
  async _open () {
    const key = (this.key !== null) ? this.key : null
    this.iddb = new DappDb(this.userIdDir, key, {
      valueEncoding: 'json'
    })
    this.dht = new USwarm(this.dhtOpts || {
      ephemeral: false
    })
    await new Promise((resolve, reject) => {
      this.dht.on('listening', () => {
        this.iddb.ready(err => {
          if (err) return reject(err)
          if (this.key === null) {
            this.isMaster = true
            this.key = this.iddb.local.key
            this.secretKey = this.iddb.local.secretKey
            this.keypair = { publicKey: this.key, secretKey: this.secretKey }
            this.isReady = true
            return resolve(null)
          }  else {
            this.isMaster = false
            this.secretKey = null
            this.keypair = null
            this.localSlaveKey = this.iddb.local.key
            this.isReady = true
            
            swarm.join(key, { lookup: true, announce: true })
            swarm.on('connection', (socket, details) => {
              pump(socket, this.iddb.replicate({ live: true }), socket)
              return resolve(null)
            })
          }
        })
      })
    })
  }
  _isAuthorized () {
    const { iddb, isMaster, isReady, localSlaveKey } = this
    if (!isReady) await this.open()
    if (!isMaster && localSlaveKey !== null && isReady) {
      iddb.authorized(localSlaveKey, (err, auth) => {
        if (err) return false
        else if (auth === true) return true
        else return false
      })
    }  else if (isMaster) {
      return true
    }  else if (!isMaster && !localSlaveKey) {
      return false
    }
  }
  async register () {
    const { dht, iddb, keypair, dk, user, isMaster, isReady } = this
    if (!isReady) await this.open()
    const { publicKey, secretKey } = keypair
    const uB = Buffer.from(user)
    return new Promise((resolve, reject) => {
      if (this._isAuthorized() && isMaster && this.checkUserAvailability()) {
        dht.muser.put(uB, { dk, keypair }, (err, { key, ...info }) => {
          if (err) return reject(err)
          if (key) {
            const defaultIdentityPrefix = '!identities!default'
            const data = { user, dk, publicKey, timestamp: new Date().toISOString() }
            const d = JSON.stringify(data)
            iddb.put(defaultIdentityPrefix, d, err => {
              if (err) return reject(err)
            })
            const resolveData = { data: d, secretKey }
            return resolve(resolveData)
          }
        })
      }  else {
        return reject(new Error('registration requires authorization to the master identity document.'))
      }
    })
  }
  checkUserAvailability () {
    const { user, isReady } = this
    if (!isReady) await this.open()
    const uB = Buffer.from(user)
    dht.on('listening', uB => {
      dht.muser.get(uB, (err, value) => {
        if (err) return true
        else return false
      })
    })
  }
  async getDefaultUser () {
    const { iddb, isReady } = this
    if (!isReady) await this.open()
    return new Promise((resolve, reject) => {
      iddb.get('!identities!default', (err, nodes) => {
        if (err) return reject(err)
        if (nodes) {
          let len = nodes.length
          let nP = len - 1
          return resolve(nodes[nP].value)
        }
      })
    })    
  }
  async getSeq () {
    const { dht, user, isReady } = this
    if (!isReady) await this.open()
    const uB = Buffer.from(user)
    return new Promise((resolve, reject) => {
      dht.on('listening', uB => {
        dht.muser.get(uB, (err, value) => {
          if (err) return reject(new Error(err))
          if (value) {
            const { seq } = value
            return resolve(seq)
          }
        })
      })
    })
  }
  async addDevice (label) {
    const { iddb, user, isMaster, isReady } = this
    if (!isReady) await this.open()
  
    const deviceId = crypto.randomBytes(32)
    return new Promise((resolve, reject) => {
      if (!this._isAuthorized()) return reject(new Error('You are not authorized to write to this ID document'))
      const cwd = DEVICE_DIR
      fs.stat(cwd, (err, stat) => {
        if (err) fs.mkdir(cwd)
      })
      if (isMaster) label = 'master'
      const deviceFilename = `${deviceId}.device`
      const deviceFile = path.join(cwd, deviceFilename)
      fs.stat(deviceFile, (err, stat) => {
        if (err) {       
          const deviceFileData = { deviceId, label, user }
          const dfd = JSON.stringify(deviceFileData)
          fs.writeFile(deviceFile, dfd)
          if (isMaster) const deviceTreeKey = '!devices!master'
          else const deviceTreeKey = `!devices!${deviceId}`
          iddb.put(deviceTreeKey, dfd, err => {
            if (err) return reject(err)
          })
          return resolve({
            dfd
          })
        } else {
          return reject(new Error('DEVICE EXISTS'))
        }
      })
    })
  }
  async getDevices () {
    const { iddb, isReady } = this
    if (!isReady) await this.open()
    return new Promise((resolve, reject) => {
      iddb.list('!devices!', list => {
         if (list) return resolve(list)
         else return reject()
      })
    })
  }
  async addSubIdentity (label, idData) {
    const { iddb, isReady } = this
    if (!isReady) await this.open()
    return new Promise((resolve, reject) => {
      if (!this._isAuthorized()) return reject(new Error('You are not authorized to write to this ID document'))
      if (!idData.username) return reject(new Error('idData must include a username.'))
      if (!idData.platform) return reject(new Error('idData must include a platform.'))
      if (!idData.address) return reject(new Error('idData must include an address.'))
      if (!idData.publicKey) return reject(new Error('idData must include a publicKey.'))
      const putKey = `!identities!${label}`
      const { platform, address, username, publicKey } = idData
      const timestamp = new Date().toISOString()
      const data = { label, platform, address, username, publicKey, timestamp }
      const d = JSON.stringify(data)
      iddb.put(putKey, d, err => {
        if (err) return reject(new Error(err))
        else return resolve()
      })
    })
  }
  async addIdentitySecret (label, secretKey) {
    const { iddb, isReady } = this
    if (!isReady) await this.open()
    return new Promise((resolve, reject) => {
      if (!this._isAuthorized()) return reject(new Error('You are not authorized to write to this ID document.'))
      const idPutKey = `!identities!${label}`
      const secretPutKey = `!identities!${label}!SECRET`
      iddb.put(idPutKey, secretKey, err => {
        if (err) return reject(new Error(err))
        else return resolve()
      })
    })
  }
  async getSecret (label) {
    const { iddb, isReady } = this
    if (!isReady) await this.open()
    return new Promise((resolve, reject) => {
      iddb.get(`!identities!${label}!SECRET`, (err, nodes) => {
        if (err) return reject(new Error(err))
        if (nodes) {
          let len = nodes.length
          let nP = len - 1
          return resolve(nodes[nP].value)
        }
      })
    })
  }
  async getSubIdentity (label) {
    const { iddb, isReady } = this
    if (!isReady) await this.open()
    return new Promise((resolve, reject) => {
      iddb.get(`!identities!${label}`, (err, nodes) => {
        if (err) return reject(new Error(err))
        if (nodes) {
          let len = nodes.length
          let nP = len - 1
          return resolve(nodes[nP].value)
        }
      })
    })
  }
  async getSubIdentity (label) {
    const { iddb, isReady } = this
    if (!isReady) await this.open()
    return new Promise((resolve, reject) => {
      iddb.get(`!identities!${label}`, (err, nodes) => {
        if (err) return reject(new Error(err))
        if (nodes) {
          let len = nodes.length
          let nP = len - 1
          return resolve(nodes[nP].value)
        }
      })
    })
  }
  async removeIdentity (label) {
    const { iddb, isReady } = this
    if (!isReady) await this.open()
    return new Promise((resolve, reject) => {
      if (!this._isAuthorized()) return reject(new Error('You are not authorized to write to this ID document.'))
      if (label === 'default') return reject(new Error('CANNOT_DEL_DEFAULT'))
      const delKey = `!identities!${label}`
      const delKeySecret = `!identities!${label}!SECRET`
      iddb.del(delKey)
      iddb.del(delKeySecret)
      return resolve()
    })
  }
  async getDb () {
    const { iddb, isReady } = this
    if (!isReady) await this.open()
    return new Promise((resolve => {
      if (iddb) return resolve(iddb)
      else return reject()
    }))
  }
  doesDefaultExist () {
    const { iddb, isReady } = this
    if (!isReady) await this.open()
    const defaultKey = '!identities!default'
    iddb.get(defaultKey, (err, nodes) => {
      if (err) return false
      if (nodes[0]) return true
    })
  }
  async getRemoteUsers () {
    const { iddb, isReady } = this
    if (!isReady) await this.open()
    return new Promise((resolve, reject) => {
      iddb.list('!user!', list => {
        if (list) return resolve(list)
        else return reject()
      })
    })
  }
  async getRemoteUser (user) {
    const { iddb, isReady } = this
    if (!isReady) await this.open()
    return new Promise((resolve, reject) => {
      iddb.get(`!user!${user}`, (err, nodes) => {
        if (err) return reject(err)
        if (nodes) {
          let len = nodes.length
          let nP = len - 1
          return resolve(nodes[nP].value)
        }
      })
    })
  }
  async addUserData (opts) {
    const { iddb, user, isReady } = this
    if (!isReady) await this.open()
    return new Promise((resolve, reject) => {
      if (!this._isAuthorized()) return reject(new Error('You are not authorized to write to this ID document.'))
      if (!opts.avatar) return reject(new Error('opts must include an avatar'))
      if (!opts.bio) return reject(new Error('opts must include a bio'))
      if (!opts.location) return reject(new Error('opts must include a location'))
      if (!opts.url) return reject(new Error('opts must include a url'))
      if (!opts.displayName) return reject(new Error('opts must include a displayName'))
      if (this.doesDefaultExist()) {
        const data = { user, avatar, bio, location, url, displayName }
        const d = JSON.stringify(data)
        const userDataKey = '!user'
        iddb.put(userDataKey, d, (err) => {
          if (err) return reject(new Error(err))
          else return resolve(null)
        })
      }  else {
        return reject(new Error('Default record must exist before writing user data'))
      }
    }) 
  }
  async addRemoteUser (opts) {
    const { iddb, user, isReady } = this
    if (!isReady) await this.open()
    return new Promise((resolve, reject) => {
      if (!this._isAuthorized()) return reject(new Error('You are not authorized to write to this ID document.'))
      if (!opts.username) return reject(new Error('opts must include a username of remote user'))
      if (!opts.publicKey) return reject(new Error('opts must include the publicKey of the remote user'))
      if (!opts.dk) return reject(new Error('opts must include the discoveryKey of the remote user'))
      const { username, dk, publicKey } = opts
      if (typeof username !== 'string') return reject(new Error('username must be a string'))
      if (typeof dk !== 'string') return reject(new Error('dk must be a string'))
      if (typeof publicKey !== 'string') return reject(new Error('publicKey must be a string'))
      const putUserKey = `!user!${username}`
      const data = { username, publicKey, dk }
      const d = JSON.stringify(data)
      iddb.put(putUserKey, d, err => {
        if (err) return reject(err)
      })
      return resolve()
    })
  }
  updateRegistration () {
    const { dht, iddb, currentKeypair: keypair, seq, dk, user, isReady } = this
    const opts = { seq, keypair, dk }
    if (!isReady) await this.open()
    return new Promise((resolve, reject) => {
      if (!this._isAuthorized()) return reject(new Error('You are not authorized to write to this ID document.'))
      if (!this.isMaster) return reject(new Error('Only the master can update registration on the DHT.'))
      dht.on('listening', () => {
        const uB = Buffer.from(user)
        dht.muser.put(uB, { keypair, dk, seq }, (err, { key, ...info }) => {
          if (err) return reject(err)
          if (key) {
            const defaultIdentityPrefix = '!identities!default'
            const data = { user, dk, publicKey, timestamp: new Date().toISOString() }
            const d = JSON.stringify(data)
            iddb.put(defaultIdentityPrefix, d, err => {
              if (err) return reject(err)
            })
            return resolve()
          }
        })
      })
    })
  }
  async getMasterDevice () {
    const { iddb, isReady } = this
    if (!isReady) await this.open()
    return new Promise((resolve, reject) => {
      iddb.get('!devices!master', (err, nodes) => {
        if (err) return reject(err)
        if (nodes) {
          let len = nodes.length
          let nP = len - 1
          return resolve(nodes[nP].value)
        }
      })
    })
  }
}