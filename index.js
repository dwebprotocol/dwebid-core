import os from 'os'
import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import assert from 'assert'
import { NanoresourcePromise, Nanoresource } from 'nanoresource-promise/emitter'
import { USwarm } from '@uswarm/core'
import DappDb from 'dappdb'

export default class DWebIdentity extends Nanoresource {
  constructor (opts = {}) {
    super()
    this.dhtOpts = opts.dhtOpts
    this.seq = opts.seq || 0
    this.homeDir = opts.homeDir || os.homedir()
    this.idDir = path.join(this.homeDir, opts.idDir || 'identities')
    this.user = opts.user
    this.userIdDir = path(this.idDir, this.user)
    this.iddb = null

    // if there is a key, that means we're not the master
    this.key = opts.key || null
    this.dk = crypto.createHash('sha256'.update(`dmessenger-${this.user}`).digest())
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
    await new Promise((resolve, reject) => {
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
          return resolve(null)
        }
      })
    })
  }
  checkUserAvailability () {
    const { dht, user } = this
    const uB = Buffer.from(user)
    dht.on('listening', uB => {
      dht.muser.get(uB, (err, value) => {
        if (err) return true
        else return false
      })
    })
  }
  async register () {
    const { dht, iddb, keypair, dk, user } = this
    const { publicKey, secretKey } = keypair
    const uB = Buffer.from(user)
    if (this.checkUserAvailability() && !this.doesDefaultExist()) {
      dht.on('listening', uB => {
        return new Promise((resolve, reject) => {
          if (!this._isAuthorized()) return reject(new Error('Not authorized.'))
          dht.muser.put(uB, { dk, keypair }, (err, { key, ...info }) => {
            if (err) return reject(err)
            if (key) {
              console.log(`${user} was successfully registered at ${key}`)
              const defaultIdentityPrefix = '!identities!default'
              const data = {
                user,
                dk,
                publicKey,
                timestamp: new Date().toISOString()
              }
              const d = JSON.stringify(data)
              iddb.put(defaultIdentityPrefix, d, err => {
                if (err) return reject(err)
              })
              const resolveData = { data: d, secretKey }
              return resolve(resolveData)
            }
          })
        })
      })
    }
  }
  _isAuthorized () {
    const { iddb, isMaster, isReady, localSlaveKey } = this
    if (!isMaster && localSlaveKey !== null && isReady) {
      iddb.authorized(localSlaveKey, (err, auth) => {
        if (err) return false
        else if (auth === true) return true
        else return false
      })
    }  else if (!isReady) {
      return new Error('ID database is not ready')
    }  else if (isMaster) {
      return true
    }  else if (!isMaster && !localSlaveKey) {
      return false
    }
  }
  async addUserData (opts) {
    return new Promise((resolve, reject) => {
      const { iddb, user } = this
      if (!this._isAuthorized()) return reject(new Error('Not authorized.'))
      if (!opts.avatar) return reject(new Error('must include an avatar'))
      if (!opts.bio) return reject(new Error('must include a bio'))
      if (!opts.location) return reject(new Error('must include a location'))
      if (!opts.url) return reject(new Error('must include a url'))
      if (!opts.displayName) return reject(new Error('must include a displayName'))
      const { avatar, bio, location, url, displayName } = opts
      if (this.doesDefaultExist() && !this.checkUserAvailability()) {
        const data = { user, avatar, bio, location, url, displayName }
        const d = JSON.stringify(data)
        const userDataKey = '!user'
        iddb.put(userDataKey, d, err => {
          if (err) return reject(new Error(err))
          else return resolve()
        })
      } else {
        return reject(new Error('A default user does not exist or the user has not been registered.'))
      }
    })
  }
  doesDefaultExist () {
    const { iddb } = this
    const defaultKey = '!identities!default'
    db.get(defaultKey, (err, nodes) => {
      if (err) return false
      if (nodes[0]) return true
    })
  }
  async addRemoteUser (opts) {
    const { iddb, user } = this
    return new Promise((resolve, reject) => {
      if (!this._isAuthorized()) return reject(new Error('Not authorized.'))
      if (!opts.username) return reject(new Error('must include a username of remote user.'))
      if (!opts.didKey) return reject(new Error('must include the didKey of the remote user.'))
      const { username, didKey } = opts
      if (typeof username === 'string') return reject(new Error('username must be a string.'))
      if (typeof didKey === 'string') return reject(new Error('didKey must be a string.'))
     const putUserKey = `!user!${username}`
     const data = { username, didKey }
     const d = JSON.stringify(data)
     iddb.put(putUserKey, d, err => {
       if (err) return reject(err)
     })
     return resolve()
    })
  }
  async getRemoteUsers () {
    const { iddb } = this
    return new Promise((resolve, reject) => {
      iddb.list('!user', list => {
        if (list) return resolve(list)
        else return reject()
      })
    })
  }
  async getRemoteUser (user) {
    const { iddb } = this
    return new Promise((resolve, reject) => {
      iddb.get(`!user!${user}`, (err, nodes) => {
        if (err) return reject(err)
        if (nodes) {
          let len = nodes.length
          let nodePos = len - 1
          return resolve(nodes[nodePos].value)
        }
      })
    })
  }
  async getDefaultUser () {
    const { iddb } = this
    return new Promise ((resolve, reject) => {
      iddb.get('!user', (err, nodes) => {
        if (err) return reject(err)
        if (nodes) {
          let len = nodes.length
          let nodePos = len - 1
          return resolve(nodes[nodePos].value)
        }
      })
    })
  }
  async getRemoteKey (username, keyType) {
    const { dht } = this
    const uB = Buffer.from(username)
    return new Promise((resolve, reject) => {
      dht.on('listening', uB => {
        dht.muser.get(uB, (err, value) => {
          if (err) return reject(new Error(err))
          if (value) {
            if (type === 'dk') {
              const { dk } = value
              return resolve(dk)
            }  else {
              const { publicKey } = value
              return resolve(publicKey)
            }
          }
        })
      })
    })
  }
  async getSeq () {
    const { dht, user } = this
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
  async updateRegistration () {
    const { dht, iddb, currentKeypair: keypair, seq, dk, user } = this
    const opts = { seq, keypair, dk }
    return new Promise((resolve, reject) => {
      if (!this._isAuthorized()) return reject(new Error('Not authorized.'))
      dht.on('listening', () => {
        const uB = Buffer.from(user)
        dht.muser.put(uB, { keypair, dk, seq }, (err, { key, ...info }) => {
          if (err) return reject(err)
          if (key) {
            console.log(`${user} was successfully updated at ${key}`)
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
  async addDevice (deviceLabel) {
    const { iddb, user } = this
    const deviceId = crypto.randomBytes(32)
    return new Promise((resolve, reject) => {
      if (!this._isAuthorized()) return reject(new Error('Not authorized.'))
      const cwd = DEVICE_DIR
      fs.stat(cwd, (err, stat) => {
        if (err) fs.mkdir(cwd)
      })
      const deviceFilename = `${deviceId}.device`
      const deviceFile = path.join(cwd, deviceFilename)
      fs.stat(deviceFile, (err, stat) => {
        if (err) {
          const deviceFileData = { deviceId, user, deviceLabel }
          const dfd = JSON.stringify(deviceFileData)
          fs.writeFile(deviceFile, dfd)
          const deviceTreeKey = `!devices!${deviceLabel}`
          iddb.put(deviceTreeKey, dfd, err => {
            if (err) return reject(err)
          })
          return resolve({
            stat: stat,
            dfd
          })
        } else {
          return reject(new Error('DEVICE_EXISTS'))
        }
      })
    })
  }
  async getDevices () {
    const { iddb } = this
    return new Promise((resolve, reject) => {
      iddb.list('!devices!', list => {
        if (list) return resolve(list)
        else return reject()
      })
    })
  }
  async addSubIdentity (label, idData) {
    const { iddb } = this
    return new Promise((resolve, reject) => {
      if (!this._isAuthorized()) return reject(new Error('Not authorized.'))
      if (!idData.username) return reject(new Error('idData must include a username'))
      if (!idData.platform) return reject(new Error('idData must include a platform'))
      if (!idData.address) return reject(new Error('idData must include an address'))
      if (!idData.publicKey) return reject(new Error('idData must include a publicKey'))
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
    const { iddb } = this
    return new Promise((resolve, reject) => {
      if (!this._isAuthorized()) return reject(new Error('Not authorized.'))
      const secretPutKey = `!identities!${label}!SECRET`
      iddb.put(secretPutKey, secretKey, err => {
        if (err) return reject(new Error(err))
        else return resolve()
      })
    })
  }
  async getSecret (label) {
    const { iddb } = this
    return new Promise((resolve, reject) => {
      iddb.get(`!identities!${label}!SECRET`, (err, nodes) => {
        if (err) return reject(new Error(err))
        if (nodes) {
          let len = nodes.length
          let nodePos = len - 1
          return resolve(nodes[nodePos].value)
        }
      })
    })
  }
  async getSubIdentity (label) {
    const { iddb } = this
    return new Promise((resolve, reject) => {
      iddb.get(`!identities!${label}`, (err, nodes) => {
        if (err) return reject(new Error(err))
        if (nodes) {
          let len = nodes.length
          let nodePos = len - 1
          return resolve(nodes[nodePos].value)
        }
      })
    })
  }
  async removeIdentity (label) {
    const { iddb } = this
    return new Promise((resolve, reject) => {
      if (!this._isAuthorized()) return reject(new Error('Not authorized.'))
      if (label === 'default') return reject(new Error('CANNOT_DEL_DEFAULT'))
      const delKey = `!identities!${label}`
      const delKeySecret = `!identities!${label}!SECRET`
      iddb.del(delKey)
      iddb.del(delKeySecret)
      return resolve()
    })
  }
  async getDb () {
    const { iddb } = this
    return new Promise((resolve) => {
      if (iddb) return resolve(iddb)
      else return reject()
    }) 
  }
}