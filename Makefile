CC                     = clang
CFLAGS                 = $(NIX_CFLAGS_COMPILE)

#add your library dependencies here
DEPS                   = -lnng -lmbedtls -lmbedcrypto -leverest -lmbedx509 -lprotobuf-c -luuid
PROJECT_NAME           = nngio
PROJECT_NAME_UPPERCASE = NNGIO

# Define the binaries and libraries to build
# BINS are the list of production binaries to build
BINS                   =
# TEST_BINS are the list of test binaries to build
TEST_BINS              = transport protobuf management
# LIBS are the list of production libraries to build
LIBS                   = transport protobuf management
# MOCK_LIBS are the list of mock libraries to build
MOCK_LIBS              = transport
# HAS_PROTO are the libraries that have protobuf definitions
HAS_PROTO              = protobuf management

# Define how we are going to build the project
BUILD_DIR             ?= build
INCLUDE                = ./include
STATIC_LIBS            = $(addprefix $(BUILD_DIR)/lib$(PROJECT_NAME)_, $(addsuffix .a, $(LIBS)))
MOCK_STATIC_LIBS       = $(addprefix $(BUILD_DIR)/libmock$(PROJECT_NAME)_, $(addsuffix .a, $(MOCK_LIBS)))
SHARED_LIBS            = $(addprefix $(BUILD_DIR)/lib$(PROJECT_NAME)_, $(addsuffix .so, $(LIBS)))
MOCK_SHARED_LIBS       = $(addprefix $(BUILD_DIR)/libmock$(PROJECT_NAME)_, $(addsuffix .so, $(MOCK_LIBS)))
BUILD_BINS             = $(filter-out %.pb-c.o, $(addprefix $(BUILD_DIR)/$(PROJECT_NAME)_, $(BINS)))
BUILD_TEST_BINS        = $(addprefix $(BUILD_DIR)/test_, $(TEST_BINS))
# Note: I only want static libs, but you can enable shared libs if you want
BUILD_LIBS             = $(STATIC_LIBS) # $(SHARED_LIBS)
BUILD_MOCK_LIBS        = $(MOCK_STATIC_LIBS) # $(MOCK_SHARED_LIBS)
BUILD_PROTO            = $(addprefix $(BUILD_DIR)/lib$(PROJECT_NAME)_, $(addsuffix .pb-c.o, $(HAS_PROTO)))
INCLUDE_PROTO          = $(addprefix $(BUILD_DIR)/lib$(PROJECT_NAME)_, $(addsuffix .pb-c.h, $(HAS_PROTO)))


# uppercase all letters in the mock libs variable
MOCK_LIBS_UPPERCASE    = $(shell echo $(MOCK_LIBS) | tr '[:lower:]' '[:upper:]')
# create preprocessor defines for each mock lib in the format `-D CALLHOME_MOCK_<LIB_NAME>=1`
MOCK_FLAGS             = $(foreach lib,$(MOCK_LIBS_UPPERCASE),-D $(PROJECT_NAME_UPPERCASE)_MOCK_$(lib)=1)

# if we are debugging, we want to add debug flags
ifdef $(PROJECT_NAME_UPPERCASE)_DEBUG
# if you want to look at postprocessed output, uncomment the next line
#NIX_CFLAGS_COMPILE += -C -E
NIX_CFLAGS_COMPILE    += -g -O0 -D $(PROJECT_NAME_UPPERCASE)_DEBUG=1
endif

# add local include directory to the include path so that our libraries and
# binaries can find the headers
# also addd binary directory to the include path so that generated protobuf
# files can be found
NIX_CFLAGS_COMPILE    += -isystem $(INCLUDE) -isystem $(BUILD_DIR)

# The default goal is to build, test, and generate an install directory
.DEFAULT_GOAL         := all

STATIC_LIBS_GROUPED = -Wl,--start-group $(foreach lib,$(STATIC_LIBS),-l:./$(lib)) -Wl,--end-group

# Build protobuf files
$(INCLUDE_PROTO): $(BUILD_PROTO)
$(BUILD_PROTO): $(BUILD_DIR)/lib$(PROJECT_NAME)_%.pb-c.o:
	echo "Generating protobuf files: $@"
	mkdir -p $(BUILD_DIR)
	protoc --c_out=$(BUILD_DIR) --proto_path=$* $*/lib$(PROJECT_NAME)_$*.proto
	$(CC) -c $(BUILD_DIR)/lib$(PROJECT_NAME)_$*.pb-c.c -o $@ -fPIC

# Build binaries
$(BUILD_DIR)/$(PROJECT_NAME)_%: NIX_CFLAGS_COMPILE += $(STATIC_LIBS_GROUPED)
$(BUILD_DIR)/$(PROJECT_NAME)_%: $(BUILD_LIBS)
	echo "Building Binary: $@"
	mkdir -p $(BUILD_DIR)
	$(CC) $(BUILD_PROTO) $*/$(PROJECT_NAME)_$*.c -o $@ -L. -isystem $* $(NIX_CFLAGS_COMPILE) $(DEPS)

# Build static libraries
$(BUILD_DIR)/lib$(PROJECT_NAME)_%.a:
	echo "Building Static Library: $@"
	mkdir -p $(BUILD_DIR)
	$(CC) -c $(BUILD_PROTO) $*/lib$(PROJECT_NAME)_$*.c -o $(subst .a,.o,$@) $(NIX_CFLAGS_COMPILE) -fPIC
	ar r $@ $(subst .a,.o,$@) >/dev/null 2>&1

# Build shared libraries
$(BUILD_DIR)/lib$(PROJECT_NAME)_%.so: $(BUILD_DIR)/lib$(PROJECT_NAME)_%.a
	echo "Building Shared Library: $@"
	mkdir -p $(BUILD_DIR)
	$(CC) -shared -o $@ $(subst .so,.o,$@)

# Create list of librariest that do not have mock versions
NON_MOCK_LIBS = $(filter-out $(MOCK_LIBS),$(LIBS))
NON_MOCK_STATIC_LIBS = $(addprefix $(BUILD_DIR)/lib$(PROJECT_NAME)_, $(addsuffix .a, $(NON_MOCK_LIBS)))
MOCK_AND_NON_MOCK_STATIC_LIBS = $(MOCK_STATIC_LIBS) $(NON_MOCK_STATIC_LIBS)
MOCK_STATIC_LIBS_GROUPED = -Wl,--start-group $(foreach lib,$(MOCK_AND_NON_MOCK_STATIC_LIBS),-l:./$(lib)) -Wl,--end-group
# Build test binaries
ifdef NNGIO_MOCK_TRANSPORT
$(BUILD_DIR)/test_%: NIX_CFLAGS_COMPILE += $(MOCK_STATIC_LIBS_GROUPED) -D NNGIO_MOCK_TRANSPORT=1
$(BUILD_DIR)/test_%: $(BUILD_MOCK_LIBS)
	echo "Building Test Binary: $@"
	mkdir -p $(BUILD_DIR)
	$(CC) $(BUILD_PROTO) $*/test_$*.c -o $@ -L. -isystem $* $(NIX_CFLAGS_COMPILE) $(DEPS)
else
$(BUILD_DIR)/test_%: NIX_CFLAGS_COMPILE += $(STATIC_LIBS_GROUPED)
$(BUILD_DIR)/test_%: $(BUILD_LIBS)
	echo "Building Test Binary: $@"
	mkdir -p $(BUILD_DIR)
	$(CC) $(BUILD_PROTO) $*/test_$*.c -o $@ -L. -isystem $* $(NIX_CFLAGS_COMPILE) $(DEPS)
endif

# Build mock static libraries
$(BUILD_DIR)/libmock$(PROJECT_NAME)_%.a: NIX_CFLAGS_COMPILE += $(MOCK_FLAGS)
$(BUILD_DIR)/libmock$(PROJECT_NAME)_%.a:
	echo "Building Mock Static Library: $@"
	mkdir -p $(BUILD_DIR)
	$(CC) -c $(BUILD_PROTO) $*/libmock$(PROJECT_NAME)_$*.c -o $(subst .a,.o,$@) -isystem $* $(NIX_CFLAGS_COMPILE) -fPIC
	ar r $@ $(subst .a,.o,$@) >/dev/null 2>&1

# Build mock shared libraries
$(BUILD_DIR)/libmock$(PROJECT_NAME)_%.so: NIX_CFLAGS_COMPILE += $(MOCK_FLAGS)
$(BUILD_DIR)/libmock$(PROJECT_NAME)_%.so: $(BUILD_DIR)/libmock$(PROJECT_NAME)_%.a
	echo "Building Mock Shared Library: $@"
	mkdir -p $(BUILD_DIR)
	$(CC) -shared -o $@ $(subst .so,.o,$@)

# Generate documentation using Doxygen
$(BUILD_DIR)/docs:
	mkdir -p $(BUILD_DIR)/docs
	doxygen Doxyfile
	mv html $(BUILD_DIR)/docs/html
	mv latex $(BUILD_DIR)/docs/latex

# Create the build directory if it does not exist
$(BUILD_DIR): $(BUILD_LIBS) $(BUILD_BINS) $(BUILD_MOCK_LIBS) $(BUILD_TEST_BINS) $(BUILD_DIR)/docs

# Allow overriding the target output directory
# For my purposes, this is overridden by the nix build system so that it can
# generate a proper output directory structure for the nngio derivation.
OUTPUT_DIR         ?= out
# Build output distribution for nix
$(OUTPUT_DIR): $(BUILD_DIR)
	mkdir -p $(OUTPUT_DIR)
	mkdir -p $(OUTPUT_DIR)/bin
	# mv $(BUILD_BINS) $(OUTPUT_DIR)/bin
	mkdir -p $(OUTPUT_DIR)/bin/test
	mv $(BUILD_TEST_BINS) $(OUTPUT_DIR)/bin/test
	mkdir -p $(OUTPUT_DIR)/lib
	mv $(BUILD_LIBS) $(OUTPUT_DIR)/lib
	mv $(BUILD_MOCK_LIBS) $(OUTPUT_DIR)/lib
	mkdir -p $(OUTPUT_DIR)/include/$(PROJECT_NAME)
	cp -r $(INCLUDE)/* $(OUTPUT_DIR)/include/$(PROJECT_NAME)
	mkdir -p $(OUTPUT_DIR)/docs
	cp -r $(BUILD_DIR)/docs $(OUTPUT_DIR)/docs

.PHONY: all test format docs clean

# default target builds production binaries and libraries
all: $(BUILD_PROTO) $(BUILD_DIR)

# test will build mock libraries and binaries, then run tests with valgrind
test: $(BUILD_PROTO) $(BUILD_DIR)
ifdef NNGIO_MOCK_TRANSPORT
	$(foreach test_bin,$(BUILD_TEST_BINS), \
	valgrind -s --leak-check=full \
	 --show-leak-kinds=all \
	 --track-origins=yes \
	 ./$(test_bin);)
else
	$(foreach test_bin,$(BUILD_TEST_BINS), \
	 ./$(test_bin);)
endif

proto: $(BUILD_PROTO)

# Format source code using clang-format
format:
	find . -iname '*.h' -o -iname '*.c' | xargs clang-format -i -style=google

# Clean up generated files and directories from local development
clean:
	-rm -fr $(BUILD_DIR) $(OUTPUT_DIR) **/*.o vgcore.* result html latex

