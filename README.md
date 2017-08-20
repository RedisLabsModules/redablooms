Update: this project has been suspended and superceded by http://rebloom.io
===

redablooms: scalable counting Bloom filters Redis Module
===

This is a port of the [dablooms](https://github.com/bitly/dablooms) library - a scalable, counting, Bloom filter by Justin Hines at Bitly - to a Redis module.

For background, refer to the original [README](https://github.com/bitly/dablooms/blob/master/README.md).

redablooms provides all of dabloom's functionality, but stores the data structures in Redis Strings instead of files.
Additionally, redablooms provides an automatic means for generating element ids using a sequence or server clock with rounding.

Quick start guide
---

1. Build a Redis server with support for modules.
2. Build the redablooms module: `make`
3. To load a module, Start Redis with the `--loadmodule /path/to/module.so` option, add it as a directive to the configuration file or send a `
MODULE LOAD` command.

Scaling Counting Bloom filter API
---

### `SBF.ADD key elem id [elem id ...]`

Adds one or more elements and their ids to the filter in `key`.

If `key` doesn't exist, the filter is created with the default capacity (100000) and error rate (0.05).  
Elements' `id`s are always integers, but can be provided in one of the following ways:

* An unsigned integer 'n' means the literal numeric id 'n'.
* '+[n]' means incrementing the filter's current maximum id by 'n' and using that value. By default 'n' is 1, so you can simply use the '+' sign for the default increment. You can use '+0' to use the current maximum id without incrementing it. 
* '/[n]' means the server's clock in milliseconds, divided by 'n', floored and multiplied by 'n'. By default 'n' is 1. This is useful for generating ids based on resolutions other than milliseconds, e.g. '/1000' will provide second resolutions ids, '/60000' is for minute resolution, etc.

Notes about adding multiple elements in a single call:

* The clock is sampled once per call.
* max_id may may be updated once, otherwise an error is returned.

**Reply:** Integer, the filter's current maximum id.

### `SBF.REM key elem id [elem id ...]`

Removes elements by id from the filter. `id`s  must be only 'n', '/n' or '+0'.

**Reply:** Integer, the number of elements removed.

### `SBF.CHECK key elem`

Checks if `elem` exists in `key`.

**Reply:** Integer, 1 if the element exists, 0 otherwise.

###  `SBF.INIT key capacity error-rate`

Initializes a new scaling counting Bloom filter.

Use this to specify other-than-the-default capacity and error rate for the filter.

**Reply:** String, "OK".

### `SBF.DEBUG key`

Shows the filter's meta data.

**Reply:** Array.

Counting Bloom filter API
---

### `CBF.ADD key elem [elem ...]`

Adds one or more elements the filter in `key`.

If the key doesn't exist, the filter is created with the default capacity (100000) and error rate (0.05).  

**Reply:** Integer, the count of elements in the filter.

### `CBF.REM key elem [elem ...]`

Removes elements from the filter.

**Reply:** Integer, the count of elements in the filter.

### `CBF.CHECK key elem`

Checks if `elem` exists in `key`.

**Reply:** Integer, 1 if the element exists, 0 otherwise.

###  `CBF.INIT key capacity error-rate`

Initializes a new counting Bloom filter.

Use this to specify other-than-the-default capacity and error rate for the filter.

**Reply:** String, "OK".

### `CBF.DEBUG key`

Shows the filter's meta data.

**Reply:** Array.

TODO
---

* Handle counter overflow/0 decrement - silently ignored
* Configurable counter width

Contributing
---

Issue reports, pull and feature requests are welcome.

License
---

redablooms is licensed under AGPLv3 - see [LICENSE](LICENSE).

deblooms is licensed under a very liberal license - see [LICENSE-dablooms](LICENSE-dablooms).
