ROOTDIR = $(CURDIR)/../

CC = gcc
CXX = g++

# Debug
# OPT = -g -ggdb
# Release
OPT = -O3

CFLAGS += $(OPT) -march=native
CXXFLAGS += $(OPT) -march=native -std=c++0x

LDFLAGS += $(OPT)
LIBS += -lrt

# DPDK
RTE_SDK = $(ROOTDIR)/dpdk
RTE_TARGET = x86_64-default-linuxapp-$(CC)
CFLAGS += -isystem $(RTE_SDK)/$(RTE_TARGET)/include -include rte_config.h
CXXFLAGS += -isystem $(RTE_SDK)/$(RTE_TARGET)/include -include rte_config.h
LDFLAGS += -L$(RTE_SDK)/$(RTE_TARGET)/lib 
LIBS += \
	-lethdev \
	-lrte_cmdline \
	-lrte_hash \
	-lrte_lpm \
	-lrte_malloc \
	-lrte_mbuf \
	-lrte_mempool \
	-lrte_pmd_ixgbe \
	-lrte_ring \
	-lrte_timer \
	-lrte_eal \
	-pthread \
	-lrte_pmd_ring \

HEADERS = \
	alloc.h \
	utility.h \
	net.h \
	router_conf.h \
	cpu_ticks.h \
	basic_types.h \
	hash.h \
	hashtable.h \
	conf_parser.h \

SOURCES = \
	alloc.c \
	utility.c \
	net.c \
	router_conf.c \
	cpu_ticks.c \
	hash.c \
	hashtable.c \
	conf_parser.c \

BUILDDIR = .

OBJECTS = $(patsubst %.c, $(BUILDDIR)/%.o, $(SOURCES))

PROGRAMS = \
	$(BUILDDIR)/netbench_client \
	$(BUILDDIR)/netbench_server \

default: all

all: $(PROGRAMS) $(TESTS) $(BENCHMARKS)

clean:
	rm -rf $(PROGRAMS) $(TESTS) $(BENCHMARKS) $(OBJECTS) $(BUILDDIR)/*.o

$(BUILDDIR)/netbench_client: $(BUILDDIR)/netbench_client.o $(OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

$(BUILDDIR)/netbench_server: $(BUILDDIR)/netbench_server.o $(OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

$(BUILDDIR)/%.o: %.c ${HEADERS} Makefile
	mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/%.o: %.cpp ${HEADERS} Makefile
	mkdir -p $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@
