# ABAC CLI Configuration (Modification is not recommended)
# Copyright (C) 2021 Hariyala Omakara Naga Sai Varshith

"""
Locations of various files used by the ABAC cli tool
"""

# remove "." before prod
CONFIG_ROOT = "/etc/abac/"
ABAC_MOUNT = "/sys/kernel/security/abac/"

CONFIG_USER_ATTRS_FILE = "user_attr.json"
CONFIG_OBJ_ATTRS_FILE = "obj_attr.json"
CONFIG_ENV_ATTRS_FILE = "env_attr.json"
CONFIG_POLICY_FILE = "policy.json"
CONFIG_TEE_RULES_FILE = "tee_rules.conf"
CONFIG_AVP_FILE = "avp.json"
CONFIG_PATH_SCOPE_FILE = "path_scope.json"

KERN_USER_ATTRS_FILE = "user_attr"
KERN_OBJ_ATTRS_FILE = "obj_attr"
KERN_ENV_ATTRS_FILE = "env_attr"
KERN_POLICY_FILE = "policy"
KERN_INCLUDE_PATHS_FILE = "include_paths"
KERN_EXCLUDE_PATHS_FILE = "exclude_paths"
KERN_TEE_POLICY_FILE = "tee_policy"

TEE_UPDATE_MARKER = "/var/lib/abac-tee/update.pending"
TEE_SERVICE = "abac-tee.service"
KERN_TEE_POLICY_FILE = "tee_policy"

TEE_UPDATE_MARKER = "/var/lib/abac-tee/update.pending"
TEE_SERVICE = "abac-tee.service"

SHARED_DIR = "/home/secured/"

PORT = 4848
