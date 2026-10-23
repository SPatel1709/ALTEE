SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW

CC := gcc
EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_SIGN := $(SGX_SDK)/bin/x64/sgx_sign
SGX_LIB := $(SGX_SDK)/lib64
PROTOCOL := ../abac_lsm/security/abac/include/abac_tee_protocol.h

ifeq ($(SGX_MODE),SIM)
APP_DEFINES := -DABAC_TEE_SIMULATION
URTS_LIB := sgx_urts_sim
EPID_LIB := sgx_epid_sim
TRTS_LIB := sgx_trts_sim
TSERVICE_LIB := sgx_tservice_sim
else ifeq ($(SGX_MODE),HW)
APP_DEFINES :=
URTS_LIB := sgx_urts
EPID_LIB := sgx_epid
TRTS_LIB := sgx_trts
TSERVICE_LIB := sgx_tservice
else
$(error SGX_MODE must be HW or SIM)
endif

CFLAGS := -m64 -O2 -Wall -Wextra -std=c11

APP_CFLAGS := $(CFLAGS) $(APP_DEFINES) \
        -I$(SGX_SDK)/include -Iinclude -Iinclude/test \
        -I../abac_lsm/security/abac/include

APP_LIBS := -L$(SGX_LIB) -l$(URTS_LIB) -lpthread
ATTESTATION_LIBS := -L$(SGX_LIB) -l$(EPID_LIB)

ENCLAVE_CFLAGS := $(CFLAGS) -nostdinc -fvisibility=hidden -fpie \
        -fstack-protector -I$(SGX_SDK)/include \
        -I$(SGX_SDK)/include/tlibc -Iinclude/enclave \
        -I../abac_lsm/security/abac/include

ENCLAVE_LDFLAGS := -m64 -nostdlib -nodefaultlibs -nostartfiles \
        -L$(SGX_LIB) -Wl,--no-undefined \
        -Wl,--whole-archive -l$(TRTS_LIB) -Wl,--no-whole-archive \
        -Wl,--start-group -lsgx_tstdc -lsgx_tcrypto \
        -l$(TSERVICE_LIB) -Wl,--end-group \
        -Wl,-Bstatic -Wl,-Bsymbolic -Wl,-pie,-eenclave_entry \
        -Wl,--export-dynamic -Wl,--defsym,__ImageBase=0 \
        -Wl,--gc-sections \
        -Wl,--version-script=src/enclave/Enclave.lds

.PHONY: all dirs run clean

all: build/bin/Test build/bin/abac-tee-daemon \
        build/enclave/enclave.signed.so

dirs:
	mkdir -p build/bin build/obj build/generated/untrusted \
	        build/generated/trusted build/enclave \
	        include/test include/enclave

build/generated/untrusted/Enclave_u.c include/test/Enclave_u.h &: \
        src/enclave/Enclave.edl | dirs
	$(EDGER8R) --untrusted $< --search-path src/enclave \
	        --search-path $(SGX_SDK)/include \
	        --untrusted-dir build/generated/untrusted
	mv -f build/generated/untrusted/Enclave_u.h include/test/

build/generated/trusted/Enclave_t.c include/enclave/Enclave_t.h &: \
        src/enclave/Enclave.edl | dirs
	$(EDGER8R) --trusted $< --search-path src/enclave \
	        --search-path $(SGX_SDK)/include \
	        --trusted-dir build/generated/trusted
	mv -f build/generated/trusted/Enclave_t.h include/enclave/

build/obj/test_main.o: Test/test_main.c include/attestation.h \
        include/test/Enclave_u.h $(PROTOCOL) | dirs
	$(CC) $(APP_CFLAGS) -c $< -o $@

build/obj/Daemon.o: src/daemon/Daemon.c include/attestation.h \
        include/test/Enclave_u.h $(PROTOCOL) | dirs
	$(CC) $(APP_CFLAGS) -c $< -o $@

build/obj/Attestation.o: src/attestation/Attestation.c \
        include/attestation.h include/test/Enclave_u.h \
        $(PROTOCOL) | dirs
	$(CC) $(APP_CFLAGS) -c $< -o $@

build/obj/Enclave_u.o: build/generated/untrusted/Enclave_u.c \
        include/test/Enclave_u.h | dirs
	$(CC) $(APP_CFLAGS) -c $< -o $@

build/bin/Test: build/obj/test_main.o build/obj/Attestation.o \
        build/obj/Enclave_u.o | dirs
	$(CC) $(CFLAGS) $^ -o $@ $(APP_LIBS) $(ATTESTATION_LIBS)

build/bin/abac-tee-daemon: build/obj/Daemon.o \
        build/obj/Attestation.o build/obj/Enclave_u.o | dirs
	$(CC) $(CFLAGS) $^ -o $@ $(APP_LIBS) $(ATTESTATION_LIBS)

build/obj/Enclave.o: src/enclave/Enclave.c \
        include/enclave/Enclave_t.h $(PROTOCOL) | dirs
	$(CC) $(ENCLAVE_CFLAGS) -c $< -o $@

build/obj/Enclave_t.o: build/generated/trusted/Enclave_t.c \
        include/enclave/Enclave_t.h | dirs
	$(CC) $(ENCLAVE_CFLAGS) -c $< -o $@

build/enclave/enclave.so: build/obj/Enclave.o \
        build/obj/Enclave_t.o | dirs
	$(CC) $^ -o $@ $(ENCLAVE_LDFLAGS)

build/enclave/Enclave_private_test.pem: | dirs
	openssl genrsa -3 -out $@ 3072

build/enclave/enclave.signed.so: build/enclave/enclave.so \
        build/enclave/Enclave_private_test.pem \
        src/enclave/Enclave.config.xml | dirs
	$(SGX_SIGN) sign \
	        -key build/enclave/Enclave_private_test.pem \
	        -enclave build/enclave/enclave.so \
	        -out $@ -config src/enclave/Enclave.config.xml

run: all
	./build/bin/Test

clean:
	rm -rf build
	rm -f include/test/Enclave_u.h include/enclave/Enclave_t.h
