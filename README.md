# libisolation [![Build Status](http://integrat.edby.coffee:4242/buildStatus/icon?job=libisolation/master)](http://integrat.edby.coffee:4242/job/libisolation/job/master/)

libisolation is an in-process software sandboxing library.

# Build

Libisolation uses CMake as its build system.

```ShellSession
$ mkdir build
$ cd build
$ cmake ..
$ make
```

And you can run tests by 

```ShellSession
$ make test
```

Before testing, make sure that your account is a menber of `kvm` group to make VMs.

# Contact

Open an issue on github in case you found a bug in libisolation.

# License

Dual MITL/GPL
