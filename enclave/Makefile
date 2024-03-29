include header.mk

CC=clang-3.9

APP_PATH = ..
OBJS = ecalls.o

.PHONY: all
all: enclave.signed.so

Enclave_C_Flags += -Imbedtls-2.5.1/include -I../

libmbedcrypto.a: mbedtls-2.5.1/library/libmbedcrypto.a
	@cp $^ $@
	@echo "cp $@"

%.o: %.cc
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX => $@"

%.o: %.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC => $@"

private_key.pem:
	openssl genrsa -out $@ -3 3072

enclave_t.c: enclave.edl
	@$(SGX_EDGER8R) --trusted --trusted-dir . $^
	@echo "GEN +> $@"

enclave_t.o: enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC => $@"

enclave.so: enclave_t.o $(OBJS) libmbedcrypto.a
	@$(CC) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK => $@"

enclave.signed.so: enclave.so private_key.pem
	@$(SGX_ENCLAVE_SIGNER) sign -key private_key.pem -enclave $< -out $@ -config config.xml
	@echo "SIGN => $@"

.PHONY: clean
clean:
	rm -rf *.so *.o enclave_t.*
