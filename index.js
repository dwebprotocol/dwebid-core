import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import assert from 'assert'
import idsign from '@dwebid/sign'
import { USwarm } from '@uswarm/core'
import MultiDTree from 'multi-dwebtree'
import dcrypto from '@ddatabase/crypto'

const HOME_DIR = os.homedir()
const ID_DIR = path.join(HOME_DIR, "identities")
const DEVICE_DIR = path.join(ID_DIR, "devices")

class DWebIdentity extends EventEmitter {
  constructor (opts = {}) {
    super()
    this.dhtOpts = opts.dhtOpts
    this.store = opts.store
    this.iddb = new MultiDTree(opts.store, {
      keyEncoding: 'utf-8',
      valueEncoding: 'json'
    })
    this.user = opts.user
    this.dht = new USwarm(opts.dhtOpts)
    this.keypair = idsign().keypair()
    this.dk = opts.dk || dcrypto.discoveryKey(this.keypair.publicKey)
    this.currentKeypair = opts.currentKeypair || null
    this.seq = opts.seq || 0
  }
  checkUserAvailability () {
    const { dht, user } = this
    const uB = Buffer.from(user)
    dht.on('listening', uB => {
      dht.muser-get(uB, (err, value) => {
        if (err) return true
        else return false
      })
    })
  }
  async register () {
    const { dht, iddb, keypair, dk, user } = this
    const { publicKey, secretKey } = keypair
    const uB = Buffer.from(user)
    if (this.checkUserAvailability()) {
      dht.on('listening', uB => {
        return new Promise((resolve, reject) => {
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
              await iddb.put(defaultIdentityPrefix, d)
              const resolveData = { data: d, secretKey }
              this.emit('registered', resolveData)
              resolve(resolveData)
            }
          })
        })
      })
    }
  }

  async addUserData (opts) {
    return new Promise((resolve, reject) => {
      const { iddb, user } = this
      if (!opts.avatar) return reject(new Error('opts must include an avatar'))
      if (!opts.bio) return reject(new Error('opts must include a bio'))
      if (!opts.location) return reject(new Error('opts must include a location'))
      if (!opts.url) return reject(new Error('opts must include a url'))
      if (!opts.displayName) return reject(new Error('opts must include a displayName'))
      const { avatar, bio, location, url, displayName } = opts
      if (this.doesDefaultExist() && !this.checkUserAvailability()) {
        const data = { user, avatar, bio, location, url, displayName }
        const d = JSON.stringify(data)
        const userDataKey = '!user'
        const { key } = await iddb.get(userDataKey)
        if (key === null) {
          this.emit('userdata-added', d)
          iddb.put(userDataKey, d)
          resolve(d)
        } else {
          await iddb.del(userDataKey)
          await iddb.put(userDataKey, d)
          this.emit('userdata-updated', d)
          resolve(d)
        }
      } else {
        return reject(new Error('A default user does not exist or the user has not been registered'))
      }
    })
  }

  doesDefaultExist () {
    const { iddb } = this
    const defaultKey = '!identities!default'
    const { seq, key, value } = await iddb.get(defaultKey)
    if (key === null) return false
    else return true
  }

  addRemoteUser (opts) {
    const { iddb, user } = this
    return new Promise((resolve, reject) => {
      if (!opts.username) return reject(new Error('opts must include username of remote user.'))
      if (!opts.didKey) return reject(new Error('opts must include the didKey of remote user.'))
      const { username, didKey } = opts
      if (typeof username === 'string') return reject(new Error('username must be a string'))
      if (typeof didKey === 'string') return reject(new Error('didKey must be a string'))
      const putUserKey = `!user!${username}`
      const data = { username, didKey } 
      const d = JSON.stringify(data)
      const { key } = await iddb.get(putUserKey)
      if (key === null) {
        await iddb.put(putUserKey, d)
        this.emit('added-remote-user', d)
        resolve(d)
      }  else {
        this.emit('remote-user-existed', d)
        return reject(new Error('REMOTE_ALRDY_EXISTS'))
      }
    })
  }
  getRemoteUsers () {
    const { iddb } = this
    return iddb.createReadStream({
      gte: '!users!'
    })
  }
  async getRemoteUser (user) {
    const { iddb } = this
    return new Promise((resolve, reject) => {
      const { value } = await iddb.get(`!users!${username}`)
      if (value) return resolve(value)
      else return reject()
    })
  }
  async getDefaultUser() {
    const { iddb } = this
    return new Promise((resolve, reject) => {
      const { value } = await iddb.get('!identities!default')
      if (value) return resolve(value)
      else return reject()
    })
  }
  getRemoteKey (username) {
    const { dht } = this
    const uB = Buffer.from(username)
    return new Promise((resolve, reject) => {
      dht.on('listening', uB => {
        dht.muser.get(uB, (err, value) => {
          if (err) return reject(new Error(err))
          if (value) {
            const { dk } = value
            return resolve(dk)
          }
        })
      })
    })
  }
  updateRegistration () {
    const { dht, iddb, currentKeypair: keypair, seq, dk, user } = this
    const opts = { seq, keypair, dk } 
    return new Promise((resolve, reject) => {
      const { sign } = idsign()
      const { publicKey, secretKey } = keypair
      const signature = sign(user, opts)
      dht.on('listening', () => {
        const uB = Buffer.from(user)
        dht.muser.put(uB, { keypair: { publicKey }, dk, signature, seq }, (err, { key, ...info }) => {
          if (err) return reject(err)
          if (key) {
            console.log(`${user} was successfully updated at ${key}`)
            const defaultIdentityPrefix = '!identities!default'
            const data = { user, dk, publicKey, timestamp: new Date().toISOString() }
            const d = JSON.stringify(data)
            const { key: defaultKey } = await iddb.get(defaultIdentityPrefix)
            if (defaultKey === null) {
              await iddb.put(defaultIdentityPrefix, d)
              resolve(d)
            } else {
              await iddb.del(defaultIdentityPrefix)
              await iddb.put(defaultIdentityPrefix, d)
              resolve(d)
            }
          } 
        })
      })
    })
  }
  addDevice () {
    const { iddb, user } = this
    const deviceId = crypto.randomBytes(32)
    return new Promise((resolve, reject) => {
      const cwd =  DEVICE_DIR
      fs.stat(cwd, (err, stat) => {
        if (err) fs.mkdir(cwd)
      })
      const deviceFilename = `${deviceId}.device`
      const deviceFile = path.join(cwd, deviceFilename)
      fs.stat(deviceFile, (err, stat) => {
        if (err) {
          const deviceFileData = { deviceId, user } 
          const dfd = JSON.stringify(deviceFileData)
          fs.writeFile(deviceFile, dfd)
          const deviceTreeKey = `!devices!${deviceId}`
          const { key } = await iddb.get(deviceTreeKey)
          if ( key === null ) {
            await iddb.put(deviceTreeKey, dfd)
            resolve({
              stat: stat,
              dfd
            })
          }
        } else {
          return reject(new Error('DEVICE_EXISTS'))
        }
      })
    })
  }

  getSeq () {
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
  async addSubIdentity (label, idData) {
    const { iddb } = this
    return new Promise((resolve, reject) => {
      if (!idData.username) return reject(new Error('idData must include a username'))
      if (!idData.platform) return reject(new Error('idData must include a platform'))
      if (!idData.address) return reject(new Error('idData must include an account address'))
      if (!idData.publicKey) return reject(new Error('idData must include a publicKey'))
      const putKey = `!identities!${label}`
      const { platform, address, username, publicKey } = idData
      const timestamp = new Date().toISOString()
      const data = { label, platform, address, username, publicKey, timestamp }
      const d = JSON.stringify(data)
      const { key } = await iddb.get(putKey)
      if (key === null) {
        await iddb.put(putKey, d)
        this.emit('added-sub-identity', d)
        return resolve(d)
      }  else {
        return reject(new Error('SUBID_ALRDY_EXISTS'))
      }
    })
  }
  
  async addIdentitySecret (label, secretKey) {
    const { iddb } = this
    return new Promise((resolve, reject) => {
      const idPutKey = `!identities!${label}`
      const secretPutKey = `!identities!${label}!SECRET`
      const { key } = await iddb.get(idPutKey)
      const { key: keyForSecret } = await iddb.get(secretPutKey)
      if (keyForSecret !== null) {
        return reject(new Error('Secret key already exists'))
      }
      if (key !== null && keyForSecret === null) {
        await iddb.put(secretPutKey, secretKey)
        resolve()
      }
      if (key === null && keyForSecret === null) {
        return reject(new Error('You must add the identity before adding the secretKey'))
      }
    })
  }
  
  async getSubIdentity (label) {
    const { iddb } = this
    return new Promise((resolve, reject) => {
      const { value } = await iddb.get(`!identities!${label}`)
      if (value) return resolve(value)
      else return reject()
    })
  }
  
  async getSecret (label) {
    const { iddb } = this
    return new Promise((resolve, reject) => {
      const { value } = await iddb.get(`!identities!${label}!SECRET`)
      if (value) return resolve(value)
      else return reject()
    })
  }
  
  async removeIdentity (label) {
    const { iddb } = this
    return new Promise((resolve, reject) => {
      if (label === 'default') 
      {
        return reject(new Error('CANNOT_DEL_DEFAULT'))
      }
      const delKey = `!identities!${label}`
      const delKeySecret = `!identities!${label}!SECRET`
      const { value } = await iddb.get(delKey)
      const { value: valueSecret } = await iddb.get(delKeySecret)
      if (value !== null && valueSecret !== null) {
        await iddb.del(delKey)
        await iddb.del(delKeySecret)
      }
      if (value !== null && valueSecret === null) {
        await iddb.del(delKey)
        return resolve()
      }
      if (value === null && valueSecret === null) {
        return reject()
      }
    })
  }
}