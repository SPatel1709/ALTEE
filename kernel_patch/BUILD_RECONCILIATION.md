# CentOS kernel source reconciliation

Build-tree location: `/home/catsss_17/rpmbuild/BUILD/kernel-5.14.0-742.el9/linux-5.14.0-742.el9.x86_64`
Recorded kernel release: `5.14.0-abac`
Configuration SHA256: `ded5b6e540b6951e7dc884797bea2babc80a4397984e16ade4713251e5c96452`

The configuration is a snapshot of the linked build tree.
It does not prove the running image's exact build configuration.

Local security_add_hooks third parameter: `const struct lsm_id *lsmid`
Registration decision: struct lsm_id pointer; existing registration retained

The composite object is renamed to abac_lsm.o, with abac.o as an input.

The Kconfig patch removes the second unconditional ABAC inclusion from
the inspected CentOS tree. It has NOT been applied to that tree.
It is not an integration patch against pristine CentOS sources.

The repository retains its newer attestation protocol constants and error
value. The inspected header difference did not change shared structures
or existing enum values.

These are source preparation changes. No kernel compilation, installation,
reboot, policy reload or service restart was performed.
