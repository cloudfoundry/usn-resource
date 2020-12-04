# usn-resource

A read-only (no `put`) [Concourse](https://concourse.ci) resource for tracking
[Ubuntu Security Notices](https://usn.ubuntu.com/)


## Source Configuration
 * `os` - os distro to track
   * `trusty` or `ubuntu-14.04-lts` for Ubuntu Trusty
   * `xenial` or `ubuntu-16.04-lts` for Ubuntu Xenial
   * `bionic` or `ubuntu-18.04-lts` for Ubuntu Bionic
   * ... (see filters on the USN website for more)
 * `priorities` - list of CVE priorities to trigger on
   * `medium`
   * `high`
   * `critical`
   * `unknown` when CVE reference gives http error


## `check`

Check for new USNs.

Metadata:

 * `guid` - URL to USN page


## `in`

Download USN contents.

 * `.resource/usn.json` - json file with the USN details


## `out`

Not a thing for this read-only resource.

## License

[Apache License 2.0](LICENSE)


## Development
- A simple set of tests live in `api/integration_test.go`
- After a change, building and pushing the docker image manually (it's not pipelined) is needed for most people to consume this
