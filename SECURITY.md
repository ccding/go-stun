# Security Policy

## Supported versions

Security fixes are provided on a best-effort basis for the current default
branch and the latest tagged release. Fixes are not normally backported to
older releases, so users should upgrade to the newest available version.

| Version | Supported |
| --- | --- |
| Current default branch | Yes |
| Latest tagged release | Yes |
| Older releases | No |

## Reporting a vulnerability

Please report suspected vulnerabilities through GitHub's private
[Report a vulnerability] form. Do not disclose vulnerability details in a
public issue, pull request, or discussion before a coordinated fix is
available.

Include as much of the following information as possible:

- The affected version, tag, or commit.
- The operating system, Go version, and relevant network configuration.
- A description of the issue, its security impact, and a realistic attack
  scenario.
- Minimal reproduction steps, test code, or a sanitized packet capture.
- Any known mitigations or suggested fixes.

Remove credentials and redact unrelated personal or network data from the
report. If a report needs large or sensitive attachments, start with a short
private report so the maintainers can arrange an appropriate transfer method.

## What to expect

The maintainers aim to acknowledge a report within seven days. After an
initial assessment, they will confirm whether the issue is accepted, request
additional information, or explain why it is not considered a vulnerability.
Response and remediation times depend on severity and maintainer availability.

For accepted vulnerabilities, the maintainers will work with the reporter on
a fix and coordinated disclosure. When appropriate, the resolution may include
a new release, a GitHub Security Advisory, and credit for the reporter. Please
allow time for users to upgrade before publishing technical details.

## Scope

Security-relevant reports include, but are not limited to:

- Crashes or excessive resource consumption caused by untrusted STUN packets.
- Acceptance of spoofed, malformed, or incorrectly correlated responses.
- Validation bypasses that produce unsafe behavior in the library or CLI.
- Vulnerabilities in dependencies or repository automation that directly
  affect users of `go-stun`.

The following are generally not security vulnerabilities by themselves:

- Disclosure of the public mapped address, which is the intended purpose of
  STUN.
- An unavailable or misconfigured third-party STUN server.
- An unknown or inaccurate NAT classification caused by a server that does not
  support the required RFC 3489 or RFC 5780 discovery probes.
- Issues that affect only unsupported releases and are already fixed in the
  latest version.

## Safe testing

Test only systems and networks you own or have explicit permission to assess.
Avoid disrupting public STUN services, accessing other users' data, or
performing tests that could degrade availability. Stop testing and report the
issue if you encounter sensitive data or cause unexpected impact.

[Report a vulnerability]: https://github.com/ccding/go-stun/security/advisories/new
