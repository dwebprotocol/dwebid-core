ddatabase-promisifier


A wrapper that provides conversion to/from callback/promise interfaces in DDatabase and RemoteDDatabase.

## Installation
```
npm i @ddatabase/promisifier
```

## Usage
```js
const ddatabase = require('ddatabase')
const ram = require('random-access-memory')
const { toPromises } = require('@ddatabase/promisifier')

const base = ddatabase(ram)

// A promisified DDatabase interface
const wrapper = toPromises(base)
```

## API
The API supports two methods, each one returning a compatibilty wrapper around DDatabase.

#### `const { toCallbacks, toPromises, unwrap } = require('@ddatabase/promisifier')`

`toCallbacks(base)` takes a DDatabase-like object with a Promises API, and returns a wrapper with a
callbacks interfaced.

`toPromises(base)` takes a DDatabase-like object with a callbacks API, and returns a wrapper with a
Promises interface.

`unwrap(base)` takes either a wrapper object, or a normal DDatabase, and returns a normal (callbacks API) DDatabase.

## License
MIT

