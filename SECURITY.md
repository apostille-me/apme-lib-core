# Security policy

Report vulnerabilities privately through GitHub Security Advisories for
`apostille-me/apme-lib-core`.

Never commit database URLs, provider credentials, customer records, production
catalog dumps, or decrypted migration artifacts. DPM planning inputs may name
environment variables, but must not embed their values. Generated plans require
review before any separate operator-owned apply step.
