# usn-resource

A read-only (no `put`) [Concourse](https://concourse.ci) resource for tracking
[Ubuntu Security Notices](https://usn.ubuntu.com/)


## Source Configuration

 * `os` - os distro to track
   * `ubuntu-14.04-lts` for Ubuntu Trusty
   * `ubuntu-16.04-lts` for Ubuntu Xenial
   * ... (see filters on the USN website for more)
 * `priorities` - list of CVE priorities to trigger on
   * `medium`
   * `high`
   * `critical`


## `check`

Check for new USNs.

Metadata:

 * `guid` - URL to USN page


## `in`

Download USN contents.

 * `.resource/usn.md` - markdown file with the USN contents


## `out`

Not a thing for this read-only resource.

## License

[Apache License 2.0](LICENSE)
