include sgx_defs.mk

CC := gcc

OBJS := enclave_u.o network.o att.o ias_ra.o $(OBJS)

INCLUDES = -I$(SGX_SDK)/include
LIBS := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread -Wl,-rpath=$(CURDIR) -lmbedtls

ifneq ($(SGX_MODE), HW)
	LIBS += -lsgx_uae_service_sim
else
	LIBS += -lsgx_uae_service
endif

CFLAGS := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(INCLUDES)
CPPFLAGS := $(CFLAGS) -std=c++11
CFLAGS += -std=c11

all: pitts burgh

enclave_u.c: enclave/enclave.edl
	@$(SGX_EDGER8R) --untrusted --untrusted-dir ./ $^
	@echo "GEN =>  $@"

enclave_u.o: enclave_u.c
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "CC <= $^"

pitts: client.c $(OBJS)
	@$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
	@echo "cc <= $@"

burgh: server.c $(OBJS)
	@$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
	@echo "cc <= $@"

%.o: %.c
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "CC <= $@"

.PHONY: clean
clean:
	rm -rf $(GENS) $(PROGRAM) *.o
