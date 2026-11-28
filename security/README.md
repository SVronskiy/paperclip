# Security analysis files

`vex.cdx.json` is a CycloneDX 1.5 VEX document. It records findings from software
composition analysis that do not apply to this code base, with the reason for each.
Import it into Dependency-Track next to the SBOM (project → Audit Vulnerabilities →
Apply VEX, or `POST /api/v1/vex`) and the listed findings get the analysis state
`NOT_AFFECTED` with the justification shown.

Add an entry only for a finding that is a false match (another product with the same
name, or code the component does not contain), with the source that shows it. A real
vulnerability is fixed by upgrading or removing the component, not by a VEX entry.

When a lockfile changes the version of a listed component, update its `affects`
purls; `scripts/check-vex.mjs` fails when a locked version is missing.
