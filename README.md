# usn-resource

A read-only (no `put`) [Concourse](https://concourse.ci) resource for tracking
[Ubuntu Security Notices](https://usn.ubuntu.com/)


## Source Configuration
 * `os` - os distro to track
   * `trusty` or `ubuntu-14.04-lts` for Ubuntu Trusty
   * `xenial` or `ubuntu-16.04-lts` for Ubuntu Xenial
   * `bionic` or `ubuntu-18.04-lts` for Ubuntu Bionic
   * `jammy`  or `ubuntu-22.04-lts` for Ubuntu Jammy
   * `noble`  or `ubuntu-24.04-lts` for Ubuntu Noble
   * ... (see filters on the USN website for more)
 * `priorities` - list of Ubuntu CVE [priorities](https://ubuntu.com/security/cves/about#priority) to trigger on, including:
   * `low`
   * `medium`
   * `high`
   * `critical`
   * `unknown` when CVE reference gives http error
* `severities` - list of CVSS CVE [severities](https://nvd.nist.gov/vuln-metrics/cvss) to trigger on, including:
    * `low`
    * `medium`
    * `high`
    * `critical`

The resource will trigger if _either_ the configured priorities _or_ severities match a usn.
For example, https://ubuntu.com/security/CVE-2025-9230 has a CVSS severity of `high` but a
Ubuntu priority of `medium`.

The following configuration would NOT trigger for `CVE-2025-9230`:
```yaml
- name: high-critical-priority
  type: usn
  source:
    os: ubuntu-22.04-lts
    priorities:
    - high
    - critical
```

whereas the following configuration WOULD:
```yaml
- name: high-critical-priority
  type: usn
  source:
    os: ubuntu-22.04-lts
    priorities:
    - high
    - critical
    severities:
    - high
```

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
- To run tests, use `go run github.com/onsi/ginkgo/v2/ginkgo --keep-going --trace --race -vv -r` from the root of the repository.
