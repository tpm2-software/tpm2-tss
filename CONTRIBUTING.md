# Guidelines for submitting bugs:
All non security bugs should be filed on the Issues tracker:
https://github.com/01org/tpm2-tss/issues

Security sensitive bugs should be emailed to a maintainer directly, or to Intel
via the guidelines here:
https://security-center.intel.com/VulnerabilityHandlingGuidelines.aspx

# Guideline for submitting changes:
All changes should be introduced via github pull requests. This allows anyone to
comment and provide feedback in lieu of having a mailing list. For pull requests
opened by non-maintainers, any maintainer may review and merge that pull
request. For maintainers, they either must have their pull request reviewed by
another maintainer if possible, or leave the PR open for at least 24 hours, we
consider this the window for comments.

## Patch requirements
* All tests must pass on Travis CI for the merge to occur.
* All changes must not introduce superfluous changes or whitespace errors.

## Guideline for merging changes
Changes must be merged with the "rebase" option on github to avoid merge commits.
This provides for a clear linear history.
