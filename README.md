pkgconfig-zig
================================================================================
An implementation of pkgconfig in Zig.  Makes it trivial to create static
`pkg-config` binaries for many target systems.

New Features?
================================================================================
Some features I may want to add.

```
--no-builtin-path: disable the builtin search path

--builtin-path: print the builtin colon-separated search path, i.e.
  /lib/pkgconfig:/usr/share/pkgconfig

--info: print all info about package, i.e.

  I often find myself scratching my head as to what pkg-config is doing. I end
  up using strace to figure out what ".pc" file is being opened and then
  examine it directly.  Here's an example of what I'd like to see:

  $ pkg-config --info foo
  PcFile: /lib/pkgconfig/foo.pc
  prefix=/usr
  exec_prefix=${prefix}
             =/usr
  Cflags: -I${exec_prefix}/include/foo-1.2.3
        : -I/usr/include/foo-1.2.3

```

Create Release
================================================================================
```
# example VERSION is 0.1
git tag v$VERSION
git push origin v$VERSION
rm -f pkg-config.tar
zig build tar
mv pkg-config.tar pkg-config-$VERSION.tar
xz pkg-config-$VERSION.tar
```

Then create a release and upload pkg-config-$VERSION.tar.xz to GitHub.
