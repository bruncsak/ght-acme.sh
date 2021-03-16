# Requirements to run the letsencrypt.sh program

## Utilities

### basic commands
 * `basename`
 * `expr`
 * `tail`
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

Instead of `curl` it is possible to use `wget`, if you set the `USE_WGET` shell environment variable to have value `yes`.
However, older version of `wget` won't work correctly, the support of `--content-on-error` flag is required.

## Internet access

Outbound HTTPS (443/tcp) is required towards the ACME server.
If it is not available, but the `https_proxy` shell environment variable is defined, the program will rely on that proxy.
