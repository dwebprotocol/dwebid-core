const test = require('tape')
const ddatabase = require('ddatabase')
const ram = require('random-access-memory')

const { toPromises, unwrap } = require('..')

test('cb ddatabase -> promises, simple', async t => {
  const base = ddatabase(ram, { valueEncoding: 'utf-8' })
  const wrapper = toPromises(base)
  await wrapper.ready()
  await wrapper.append('hello world')
  const block = await wrapper.get(0)
  t.same(block, 'hello world')
  t.end()
})

test('cb ddatabase -> promises, events', async t => {
  const base = ddatabase(ram, { valueEncoding: 'utf-8' })
  const wrapper = toPromises(base)

  let ready = 0
  let appended = 0
  wrapper.on('ready', () => {
    ready++
  })
  wrapper.on('append', () => {
    appended++
  })

  await wrapper.ready()
  await wrapper.append('hello world')
  t.same(ready, 1)
  t.same(appended, 1)

  t.end()
})

test('double wrapping', async t => {
  const base = ddatabase(ram, { valueEncoding: 'utf-8' })
  const wrapper = toPromises(toPromises(base))
  await wrapper.ready()
  await wrapper.append('hello world')
  const block = await wrapper.get(0)
  t.same(block, 'hello world')
  t.end()
})

test('can unwrap', async t => {
  const base = ddatabase(ram, { valueEncoding: 'utf-8' })
  const wrapper = toPromises(toPromises(base))
  t.same(base, unwrap(wrapper))
  t.same(base, unwrap(base))
  t.end()
})
