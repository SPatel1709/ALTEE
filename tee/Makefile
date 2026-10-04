SGX_SDK ?= /opt/intel/sgxsdk

CC := gcc
EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_SIGN := $(SGX_SDK)/bin/x64/sgx_sign
SGX_LIB := $(SGX_SDK)/lib64
PROTOCOL := ../abac_lsm/security/abac/include/abac_tee_protocol.h

CFLAGS := -m64 -O2 -Wall -Wextra -std=c11
APP_CFLAGS := $(CFLAGS) -I$(SGX_SDK)/include -Iinclude/test \
        -I../abac_lsm/security/abac/include
APP_LIBS := -L$(SGX_LIB) -lsgx_urts -lpthread

ENCLAVE_CFLAGS := $(CFLAGS) -nostdinc -fvisibility=hidden -fpie \
        -fstack-protector -I$(SGX_SDK)/include \
        -I$(SGX_SDK)/include/tlibc -Iinclude/enclave \
        -I../abac_lsm/security/abac/include

ENCLAVE_LDFLAGS := -m64 -nostdlib -nodefaultlibs -nostartfiles \
        -L$(SGX_LIB) -Wl,--no-undefined \
        -Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
        -Wl,--start-group -lsgx_tstdc -lsgx_tcrypto -lsgx_tservice \
        -Wl,--end-group -Wl,-Bstatic -Wl,-Bsymbolic \
        -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
        -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
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

build/obj/test_main.o: Test/test_main.c include/test/Enclave_u.h \
        $(PROTOCOL) | dirs
	$(CC) $(APP_CFLAGS) -c $< -o $@

build/obj/Daemon.o: src/daemon/Daemon.c include/test/Enclave_u.h \
        $(PROTOCOL) | dirs
	$(CC) $(APP_CFLAGS) -c $< -o $@

build/obj/Enclave_u.o: build/generated/untrusted/Enclave_u.c \
        include/test/Enclave_u.h | dirs
	$(CC) $(APP_CFLAGS) -c $< -o $@

build/bin/Test: build/obj/test_main.o build/obj/Enclave_u.o | dirs
	$(CC) $(CFLAGS) $^ -o $@ $(APP_LIBS)

build/bin/abac-tee-daemon: build/obj/Daemon.o \
        build/obj/Enclave_u.o | dirs
	$(CC) $(CFLAGS) $^ -o $@ $(APP_LIBS)

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
