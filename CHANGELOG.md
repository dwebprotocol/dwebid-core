## 1.0.0
=====
- Added promises

## 1.1.1
- On `this.dk`, dk is imported from opts or generated.
- BUG: Added this.seq, so that sequence is imported into constructor, for use with updateRegistration()
- BUG: this.username, should be this.user - as it's referenced in other methods.
- Added new getSeq method, for retrieving a user record's latest sequence