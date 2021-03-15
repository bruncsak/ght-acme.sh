# Requirements to run the letsencrypt.sh program

## Utilities

### basic commands
 * `cat`
 * `cp`
 * `rm`
 * `sed`
 * `grep`
 * `egrep`
 * `fgrep`
 * `tr`
 * `mktemp`

### non-trivial programs/utilities
 * `xxd`
 * `openssl`
 * `curl`

Instead of `curl` it is possible to use `wget`, if you set the USE_WGET variable to have value `yes`.
However, older version of wget won't work correctly, the support of `--content-on-error` flag is required.
