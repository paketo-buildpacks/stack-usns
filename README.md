# Stack-USNs

This repository monitors [the USN RSS
feed](https://ubuntu.com/security/notices/rss.xml) for new USNs, and sends
dispatches to the stack release repos:
- [Full-stack-release](https://github.com/paketo-buildpacks/full-stack-release)
- [Base-stack-release](https://github.com/paketo-buildpacks/base-stack-release)
- [Tiny-stack-release](https://github.com/paketo-buildpacks/tiny-stack-release)


The [usns file](https://github.com/paketo-buildpacks/stack-usns/blob/main/usns)
is a master list of ALL of the USNs that have been published since the
beginning of this repo's existence.
