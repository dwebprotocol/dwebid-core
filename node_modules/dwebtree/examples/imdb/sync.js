const DTree = require('../../')
const ddatabase = require('ddatabase')

const db = new DTree(ddatabase('./db', { sparse: true }))

require('@dswarm/replicator')(db.feed, {
  announce: true,
  lookup: true,
  live: true
})

db.feed.ready(function () {
  console.log('Feed key: ' + db.feed.key.toString('hex'))
})

module.exports = db
