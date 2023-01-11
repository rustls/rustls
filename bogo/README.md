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
