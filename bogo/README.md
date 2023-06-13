# BoGo

[BoGo](https://github.com/google/boringssl/tree/master/ssl/test) is the TLS test suite for boringssl, which we run against rustls as well.

## System requirements

You will need golang installed

## Running tests

```bash
$ cd bogo # from rustls repo root
$ ./runme
```

## Running a single test

```bash
$ cd bogo # from rustls repo root
$ ./runme -test "Foo;Bar" # where Foo and Bar are test names like EarlyData-Server-BadFinished-TLS13
```

## Diagnosing failures

When updating the BoGo suite it's expected that new failures will emerge. There
are often two major categories to diagnose:

### Unexpected error outputs

Often the upstream will change expected error outputs (e.g. changing from
`:DECODE_ERROR:` to `:NO_CERTS:`). The [`bogo_shim`][bogo_shim] `handle_err`
function is responsible for mapping errors in combination with the `ErrorMap`
and `TestErrorMap` data in [`config.json`][config.json]. These will typically
need updating for new error outputs or changes in error outputs.

[bogo_shim]: ../rustls/examples/internal/bogo_shim.rs
[config.json]: ./config.json

### Unhandled options

When the upstream test suite adds new options that aren't handled by Rustls the
[`bogo_shim`][bogo_shim]'s `main` fn can be updated to signal `NYI`
(not-yet-implemented) for the unhandled options. See the `// Not implemented
things` switch near the end of the function definition.

Use your best judgement to decide whether there should be a Rustls issue filed
to consider implementing the option in question.
