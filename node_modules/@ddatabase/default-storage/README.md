# @ddatabase/default-storage

Default storage provider used by dDatabase

```
npm install @ddatabase/default-storage
```

## Usage

``` js
const defaultStorage = require('@ddatabase/default-storage')

const feed = ddatabase(name => defaultStorage(name, { directory: 'feed' }))
```

## API

#### `storage = defaultStorage(name, [options])`

Makes a new random-access-storage provider using the random-access-file module.

If making a bitfield file that file will be locked to avoid parallel writers.

## License

MIT
