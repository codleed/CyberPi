---
description: Look up CVE intelligence for a product, a version or a CVE id and report the exploitability verdict
argument-hint: "[query]"
---
Look up CVE intelligence for ${1:-a product, a version or a CVE id} and report the exploitability verdict.

## Arguments

- Query: $1
- Extra instructions: $@

## Steps

1. Shape the query first. A CVE id goes straight to `cyber_cve_lookup`. A product name or a version goes to `cyber_exploit_map`, which searches the database and returns every matching CVE with the affected version ranges.
2. `cyber_cve_lookup` - pull the single record by its identifier in `cve_id`: the description, the CVSS score and vector, the CWE, the affected products and version ranges, the references, and the KEV and EPSS status.
3. `cyber_exploit_map` - map the CVE onto the products, versions and exploit primitives that are known to be affected, and cross-reference Metasploit and ExploitDB. `query` accepts a CVE id, a product name or a CPE, and `limit` bounds the number of results.
4. `cyber_exploit_search` - look for public exploits, modules and proof-of-concept code in the local ExploitDB mirror, using the search term in `query`.
5. Compare the version the target actually runs against the affected version ranges, whenever the target version is known. That comparison is the point of the lookup.

## Rules

- Use only the CyberPi tools named above. Do not query nvd.nist.gov or any other web service directly.
- If the database is stale or empty, say so and run `cyber_cve_sync` before you draw any conclusion. Use its `full` flag for a complete re-download rather than the incremental update.
- Do not inflate the risk. A CVE with a public exploit is not the same as a CVE that is being exploited in the wild, and neither is the same as the target being vulnerable.

## Report back

- The CVE id, the description, the CVSS score and vector, the CWE, and the affected products with their version ranges.
- The exploitability verdict, stated plainly: known exploited in the wild, a public exploit exists, a proof of concept exists, or theoretical only. Include the EPSS probability when it is available.
- Whether the target is affected, with the version comparison that proves it.
- The public exploit references and the path to the local exploit database entry.
- The remediation, in one or two lines.
