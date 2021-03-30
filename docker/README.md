### Notes

* The Debain builds are really just for messing about with, I'm not intending to have Docker Hub build them. These builds should be quicker than in Alpine, since there are manylinux wheels available for some of the Python modules in some of the architectures and fewer need to be built from source (which Alpine builds tend to require, due to manymusl wheels not quite being a thing yet). They're still very slow though, and probably don't need to exist.

* `Dockerfile.binary` will build Debian-binary as well as Alpine-binary (either directly or via the `builder` intermediate). All OS-specific commands (i.e apk/apt) are handled upstream in `moonbuggy2000/nuitka`.

* `CRYPTOGRAPHY_DONT_BUILD_RUST` is set for the arm32 builds (in the relevant Dockerfiles), it's the easiest way to get cryptography 3.4+ in all containers. This should be removed once rust+cryptography+QEMU+arm32 builds without a whole bunch of screwing about. (Don't dive down this rabbit hole again.)
