# Guidelines for submitting bugs:
All non security bugs should be filed on the Issues tracker:
https://github.com/01org/tpm2.0-tss/issues

Security sensitive bugs should be emailed to a maintainer directly, or to Intel
via the guidelines here:
https://security-center.intel.com/VulnerabilityHandlingGuidelines.aspx

# Guideline for submitting changes:
All changes to the source code must follow the coding standard documented
[here](doc/coding_standard_c.md).

All changes should be introduced via github pull requests. This allows anyone to
comment and provide feedback in lieu of having a mailing list. For pull requests
opened by non-maintainers, any maintainer may review and merge that pull
request. For maintainers, they either must have their pull request reviewed by
another maintainer if possible, or leave the PR open for at least 24 hours, we
consider this the window for comments.

## Patch requirements
* All tests must pass on Travis CI for the merge to occur.
* All changes must not introduce superfluous changes or whitespace errors.
* All commits should adhere to the git commit message guidlines described
here: https://chris.beams.io/posts/git-commit/ with the following exceptions.
 * We allow commit subject lines up to 80 characters.
 * Commit subject lines should be prefixed with a string identifying the
effected subsystem. If the change is spread over a number of
subsystems then the prefix may be omitted.
* All contributions must adhere to the Developers Certificate of Origin. The
full text of the DCO is here: https://developercertificate.org/. Contributors
must add a 'Signed-off-by' line to their commits. This indicates the
submitters acceptance of the DCO.

## Guideline for merging changes
Changes must be merged with the "rebase" option on github to avoid merge commits.
This provides for a clear linear history.
