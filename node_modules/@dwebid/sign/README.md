# @dwebid/sign
Methods used for creating digital signatures within a mutable user record on a [USwarm](https://github.com/dwebprotocol/uswarm)-based DHT.

## Install
```
npm install @dwebid/sign
```

## API
#### `const { keypair, sign, signable } = dwebsign()`
Call the exported function to get a `dwebsign` instance.

#### `keypair()`
Use this method to generate an assymetric keypair.
Returns an object with `{ publicKey, secretKey }`, both of which hold Buffers.

#### `sign(username, options)`
Create a signature for the user record

Options:
* `keypair` - REQUIRED, use `keypair` to generate
* `dk` - REQUIRED, the key to the identity document
* `seq` - OPTIONAL, default `0`. The sequence number of the value

#### `signable(username, options)`
Returns a concatenated Buffer of the username, dk and seq that is used by the sign() method.