# Security Policy

## Supported Versions

We provide patch updates for each minor release for at least one year
from its initial release.
Check the initial release date for your minor version at:
   - <https://github.com/tpm2-software/tpm2-tss/releases>

## Reporting a Vulnerability

The preferred method is to report security vulnerabilities by opening a
GitHub Security Advisory (GHSA) to coordinate disclosure.
Alternatively, write an encrypted email to all maintainers using the keys
listed in [MAINTAINERS](MAINTAINERS.md).

Please do not create temporary private forks when coordinating a GHSA.
They complicate mitigation and release coordination and clutter the
organization's repository list.

## Security Reporting Guidelines

### Tracking

When a maintainer is notified of a security vulnerability, they *must*
create a GitHub Security Advisory (GHSA) per the instructions at:
  - <https://docs.github.com/en/code-security/repository-security-advisories/about-github-security-advisories-for-repositories>

Maintainers *should* use GitHub's optional feature to request that a CVE be
issued.
Alternatively, Red Hat has acted as a CNA for us in the past, but GitHub is
the preferred issuing CNA.

### Publishing

Before publication, maintainers *must* ensure the GHSA summary contains no
proof-of-concept (PoC) exploit code and *must* move any such code to a
private comment on the advisory.

Once ready, maintainers *should* publish the security advisory as outlined
at:
  - <https://docs.github.com/en/code-security/repository-security-advisories/publishing-a-repository-security-advisory>

Maintainers *must* ensure the CVE is published and have new release
versions ready to publish at the same time as the advisory/CVE.
Maintainers *should* strive to keep the turnaround from report to release
under 60 days.

Reporters are credited unless they request otherwise.
