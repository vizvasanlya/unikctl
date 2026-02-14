## Xen Integration Versioning

Xen functionality is broken up into a hypervisor <-> library relationship.
Even if those are decoupled, they need to be within an acceptable version distance of each other.
We currently have confirmed integration with Xen 4.19 and possibly the 4.20-rc versions that are in the works.

### Changing Xen versions from 4.19

In order to make krafkit work with an older version, it must be recompiled for that version.
Fastest way to do this would be to follow this set of commands:
1. Change the version to an older one:
```console
$ find . -type f -exec sed -i 's/4.19/4.18/g' {} +
```

2. Get the library version corresponding to that one:
```console
$ go get -u xenbits.xenproject.org/git-http/xen.git/tools/golang/xenlight@RELEASE-4.18.0 && go mod tidy
```

3. Rebuild the unikctl build environment:
```console
$ make buildenv-xen buildenv-myself-full buildenv-myself
```

4. Start the build container:
```console
$ docker run --rm -it --entrypoint /bin/bash -v .:/tmp/unikctl unikctl.sh/myself-full:latest
```

5. Rebuild unikctl:
```console
$ cd /tmp/unikctl && make unikctl
```

That's it!
Your binary is now located at `dist/unikctl`.
Remember that you need to use `sudo` in order to interact with Xen.
