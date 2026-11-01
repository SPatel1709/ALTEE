# SPDX-License-Identifier: GPL-2.0-only
ccflags-y := -I$(srctree)/security/abac/include/
obj-$(CONFIG_SECURITY_ABAC) := abac_lsm.o

abac_lsm-y := avp.o abacfs.o abac.o env.o obj.o pathcfg.o policy.o resolve.o tee_bridge.o tree.o user.o
