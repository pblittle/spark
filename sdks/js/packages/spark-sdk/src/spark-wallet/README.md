# Known issues

console.error log when running SparkWallet in bare:

```sh
Error: Expected Module.\_resolveFilename to be a function (was: undefined) - aborting!
Please report this error as an issue related to Node.js v1.21.1 at https://github.com/nodejs/require-in-the-middle/issues
```

This comes from our import of @opentelemetry/insturmentation for tracing which imports require-in-the-middle from Node.js - support for this module will not be included in bare. It's possible that we can load the tracing requirements in a different way but this requires additional investigation. Internal ticket LIG-8098.
