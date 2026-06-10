#Setup

Make sure you create a setup.sh, build.sh, test.sh, and LET_IT_RIP.sh that contain all project setup scripts/commands used - NEVER build/test/run the code in this repo outside of these scripts, NEVER commit or push without running these either. Make them idempotent so that each build.sh can run setup.sh and skip things already set up, each test.sh can run build.sh, each LET_IT_RIP runs test.sh

use go 1.26

Use https://pkg.go.dev/github.com/google/certificate-transparency-go and its client/, dnsclient/, scanner/, and scanlog and ctcclient to download and verify certificate transparency logs from https://mon.sycamore.ct.letsencrypt.org/2026h1/tile/data/ with data available at the endpoints specified by the documentation (which may be out of date/inaccurate) from https://github.com/C2SP/C2SP/blob/main/static-ct-api.md 

Extract the domains from X509v3 Subject Alternative Name, the Issuer (organization name), and all other information from:
Issuer: (CA ID: 204411)
            commonName                = Sectigo Public Server Authentication CA OV R36
            organizationName          = Sectigo Limited
            countryName               = GB
        Validity
            Not Before: Mar 13 00:00:00 2026 GMT
            Not After : Sep 27 23:59:59 2026 GMT
        Subject:
            commonName                = cityvoip-cm-presence2-publisher-cup-xmpp-ms.sf.gov
            organizationName          = City and County of San Francisco
            stateOrProvinceName       = California
            countryName               = US


Write this Issuers and Subjects to separate SQLite files, but use the CA ID as a foreign key to link Subjects back to their Issuer. Implement this ingestion service as a gRPC API taking protobuf messages with a target log batch, SQLite DB output URIs, and monitoring API root, and returning a stream of Subject URLs to the client.

Continue implementing this tool until you can successfully verify a roundtrip with these example inputs:
	1000 records, /tmp/urls/, https://mon.sycamore.ct.letsencrypt.org/2026h1/tile/data/
Document your progress and useful tools/commands in CLAUDE-PROGRESS-LOG.md . 
