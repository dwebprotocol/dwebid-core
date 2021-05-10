import path from 'path'
import crypto from 'crypto'
import assert from 'assert'
import { EventEmitter } from 'events'
import dwebsign from '@dswarm/dwebsign'
import { USwarm } from '@uswarm/core'
import MultiDTree from 'multi-dwebtree'

const HOME_DIR = os.homedir()
const ID_DIR = path.join(HOME_DIR, "identities") // home/identities/ on Mac
const DEVICE_DIR = path.join(ID_DIR, "devices") // home/identities/devices on Mac

class DWebIdentity extends EventEmitter {
  constructor (opts = {}) {
    super()
    // TODO: Add assert checks on options
    this.dhtOpts = opts.dhtOpts
    this.base = opts.base
    this.identityDb = new MultiDTree(opts.base, {
      keyEncoding: 'utf-8',
      valueEncoding: 'json'
    })
    this.username = opts.username
    this.dht = new USwarm(opts.dhtOpts)
  }
  checkUserAvailability () {
    const { dht, user } = this
    const uB = Buffer.from(user)
    dht.on('listening', (uB) => {
      dht.muser.get(uB, (err, value) => {
        if (err) return true
        if (value) return false
      })
    })
  }
  register () {
    const { dht, identityDb, user } = this
    const { keypair } = dwebsign()
    const { publicKey, secretKey } = keypair()
    const keypair = {
      publicKey,
      secretKey
    }
    const uB = Buffer.from(user)
    // TODO: Get key from Multi DTree's "Diff" feed
    const dk = null
    if (this.checkUserAvailability() === true) {
      dht.on('listening', (uB) => {
        dht.muser.put(uB, {
          dk,
          keypair
        }, (err, { key, ...info }) => {
         if (err) return console.log(err)
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
           await identityDb.put(defaultIdentityPrefix, d)
           const eventData = {
             data: d,
             secretKey
           }
           const ed = JSON.stringify(eventData)
           this.emit('registered', ed)
         }
       })
      })
    } 
  }
  addUserData (opts) {
    const { identityDb, user } = this
    if (!opts.avatar) opts.avatar = null
    if (!opts.bio) opts.bio = null
    if (!opts.location) opts.location = null
    if (!opts.url) opts.url = null
    if (!opts.displayName) opts.displayName = null
    const { avatar, bio, location, url, displayName } = opts
    if (this.doesDefaultExist() === true && this.checkUserAvailability() === false) {
      const data = {
        username,
        avatar,
        bio,
        location,
        url,
        displayName
      }
      const d = JSON.stringify(data)
      const userDataKey = '!user'
      const { key } = await identityDb.get(userDataKey)
      if (key === null) {
        identityDb.put(userDataKey, d)
        this.emit('userdata-added', d)
      } else {
        await identityDb.del(userDataKey)
        await identityDb.put(userDataKey, d)
        this.emit('userdata-updated', d)
      }
    } else {
      throw new Error('A default user does not exist or the user has not been registered.')
    }
  }
  doesDefaultExist () {
    const { identityDb } = this
    const defaultKey = '!identities!default'
    const { seq, key, value } = await identityDb.get(defaultKey)
    if (key === null) {
      return false
    } else {
      return true
    }
  }
  addRemoteUser (opts) {
    const { identityDb, user } = this
    if (!opts.username) throw new Error('opts must include username of remote user.')
    if (!opts.didKey) throw new Error('opts must include the didKey of the remote user.')
    const { username, didKey } = opts
    assert(typeof username === 'string', 'username must be a string')
    assert(typeof didKey === 'string', 'didKey must be a string.')
    const putUserKey = `!users!${username}`
    const data = {
      username,
      didKey
    }
    const d = JSON.stringify(data)
    const { key } = await identityDb.get(putUserKey)
    if (key === null) {
      await identityDb.put(putUserKey, d)
      this.emit('added-remote-user', d)
    } else {
      await identityDb.del(putUserKey)
      this.emit('remote-user-deleted', d)
      await identityDb.put(putUserKey, d)
      this.emit('remote-user-updated', d)
    }
  }
  getRemoteUsers () {
    const { identityDb } = this
    return db.createReadStream({
      gte: '!users!'
    })
  }
  getRemoteUser (user) {
    const { identityDb } = this
    const { value } = await identityDb.get(`!users!${username}`)
    return value
  }
  getDefaultUser () {
    const { identityDb } = this
    const { value } = await identityDb.get('!identities!default')
    return value
  }
  getRemoteUserKey (username) {
    const { dht } = this
    const uB = Buffer.from(username)
    dht.on('listening', (uB) => {
      dht.muser.get(uB, (err, value) => {
        if (err) throw new Error(err)
        if (value) {
          const { dk } = value
          return dk
        }
      })
    })
  }
  updateRegistration (opts) {
    const { dht, identityDb, user } = this
    if (!opts.seq) throw new Error('opts must include a seq')
    if (!opts.keypair.secretKey) throw new Error('opts must include a privateKey')
    if (!opts.keypair.publicKey) throw new Error('opts must include a secretKey')

    const { seq, keypair } = opts
    const { sign } = dwebsign()
    const { publicKey, secretKey } = keypair
    const signature = sign(user, { keypair, seq })
    const uB = Buffer.from(user)
    dht.on('listening', () => {
      dht.muser.put(uB, {
        keypair: {
          publicKey
        },
        dk,
        signature,
        seq
      }, (err, { key, ...info }) => {
        if (err) return console.log(err)
        if (key) {
          console.log(`${user} was successfully updated at ${key}`);
          const defaultIdentityPrefix = '!identities!default'
          const data = {
            user,
            dk,
            publicKey,
            timestamp: new Date().toISOString()
          }
          const d = JSON.stringify(data)
          if (this.doesDefaultExist() === false) {
            identityDb.put(defaultIdentityPrefix, d)
          } else {
            identityDb.del(defaultIdentityPrefix)
            identityDb.put(defaultIdentityPrefix, d)
          }
        }
      })
    })
  }
  addDevice () {
    const { identityDb, user } = this
    const deviceId = crypto.randomBytes(32)
    // check to see if the device has already been added locally
    const cwd = DEVICE_DIR
    fs.stat(cwd, (err, stat) => {
      if (err) fs.mkdir(cwd)
    })
    const deviceFilename = `${deviceId}.device`
    const deviceFile = path.join(cwd, deviceFilename)
    fs.stat(deviceFile, (err, stat) => {
      if (err) {
        const deviceFileData = {
          deviceId,
          user
        }
        const dfd = JSON.stringify(deviceFileData)
        fs.writeFile(deviceFile, dfd)
        const deviceTreeKey = `!devices!${deviceId}`
        const { key } = await identityDb.get(deviceTreeKey)
        if (key === null) {
          await identityDb.put(deviceTreeKey, dfd)
        }
        return {
          stat: stat,
          dfd
        }
      } else {
        throw new Error('Device identity already exists within identity document and on the actual device itself.')
      }
    })
  }
}

module.exports = DWebIdentity