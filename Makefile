CC                     = clang
CFLAGS                 = $(NIX_CFLAGS_COMPILE)

#add your library dependencies here
DEPS                   = -lnng -lmbedtls -lmbedcrypto -leverest -lmbedx509 # -lauthorized_keys -lnng -lmbedtls -lmbedcrypto -leverest -lmbedx509
PROJECT_NAME           = nngio
PROJECT_NAME_UPPERCASE = NNGIO

# Define the binaries and libraries to build
# BINS are the list of production binaries to build
BINS                   = main
# TEST_BINS are the list of test binaries to build
TEST_BINS              = main
# LIBS are the list of production libraries to build
LIBS                   = main
# MOCK_LIBS are the list of mock libraries to build
MOCK_LIBS              = main

# Define how we are going to build the project
BUILD_DIR             ?= build
INCLUDE                = ./include
STATIC_LIBS            = $(addprefix $(BUILD_DIR)/lib$(PROJECT_NAME)_, $(addsuffix .a, $(LIBS)))
MOCK_STATIC_LIBS       = $(addprefix $(BUILD_DIR)/libmock$(PROJECT_NAME)_, $(addsuffix .a, $(LIBS)))
SHARED_LIBS            = $(addprefix $(BUILD_DIR)/lib$(PROJECT_NAME)_, $(addsuffix .so, $(LIBS)))
MOCK_SHARED_LIBS       = $(addprefix $(BUILD_DIR)/libmock$(PROJECT_NAME)_, $(addsuffix .so, $(LIBS)))
BUILD_BINS             = $(addprefix $(BUILD_DIR)/$(PROJECT_NAME)_, $(BINS))
BUILD_TEST_BINS        = $(addprefix $(BUILD_DIR)/test_, $(TEST_BINS))
BUILD_LIBS             = $(STATIC_LIBS) $(SHARED_LIBS)
BUILD_MOCK_LIBS        = $(MOCK_STATIC_LIBS) $(MOCK_SHARED_LIBS)


# uppercase all letters in the mock libs variable
MOCK_LIBS_UPPERCASE    = $(shell echo $(MOCK_LIBS) | tr '[:lower:]' '[:upper:]')
# create preprocessor defines for each mock lib in the format `-D CALLHOME_MOCK_<LIB_NAME>=1`
MOCK_FLAGS             = $(foreach lib,$(MOCK_LIBS_UPPERCASE),-D $(PROJECT_NAME_UPPERCASE)_MOCK_$(lib)=1)

# if we are debugging, we want to add debug flags
ifdef DEBUG
# if you want to look at postprocessed output, uncomment the next line
#NIX_CFLAGS_COMPILE += -C -E
NIX_CFLAGS_COMPILE    += -g -O0 -D $(PROJECT_NAME_UPPERCASE)_DEBUG=1
endif

# add local include directory to the include path so that our libraries and
# binaries can find the headers
NIX_CFLAGS_COMPILE    += -isystem $(INCLUDE)

# The default goal is to build, test, and generate an install directory
.DEFAULT_GOAL         := all

STATIC_LIBS_GROUPED = -Wl,--start-group $(foreach lib,$(STATIC_LIBS),-l:./$(lib)) -Wl,--end-group
# Build binaries
$(BUILD_DIR)/$(PROJECT_NAME)_%: NIX_CFLAGS_COMPILE += $(STATIC_LIBS_GROUPED)
$(BUILD_DIR)/$(PROJECT_NAME)_%: $(BUILD_LIBS)
	echo "Building Binary: $@"
	mkdir -p $(BUILD_DIR)
	$(CC) $*/$(PROJECT_NAME)_$*.c -o $@ -L. -isystem $* $(NIX_CFLAGS_COMPILE) $(DEPS)

# Build static libraries
$(BUILD_DIR)/lib$(PROJECT_NAME)_%.a:
	echo "Building Static Library: $@"
	mkdir -p $(BUILD_DIR)
	$(CC) -c $*/lib$(PROJECT_NAME)_$*.c -o $(subst .a,.o,$@) -fPIC
	ar r $@ $(subst .a,.o,$@) >/dev/null 2>&1

# Build shared libraries
$(BUILD_DIR)/lib$(PROJECT_NAME)_%.so: $(BUILD_DIR)/lib$(PROJECT_NAME)_%.a
	echo "Building Shared Library: $@"
	mkdir -p $(BUILD_DIR)
	$(CC) -shared -o $@ $(subst .so,.a,$@)

MOCK_STATIC_LIBS_GROUPED = -Wl,--start-group $(foreach lib,$(MOCK_STATIC_LIBS),-l:./$(lib)) -Wl,--end-group
# Build test binaries
ifdef TEST_MOCK
$(BUILD_DIR)/test_%: NIX_CFLAGS_COMPILE += $(MOCK_STATIC_LIBS_GROUPED) -D NNGIO_MOCK_MAIN=1
$(BUILD_DIR)/test_%: $(BUILD_MOCK_LIBS)
	echo "Building Test Binary: $@"
	mkdir -p $(BUILD_DIR)
	$(CC) $*/test_$*.c -o $@ -L. -isystem $* $(NIX_CFLAGS_COMPILE) $(DEPS)
else
$(BUILD_DIR)/test_%: NIX_CFLAGS_COMPILE += $(STATIC_LIBS_GROUPED)
$(BUILD_DIR)/test_%: $(BUILD_LIBS)
	echo "Building Test Binary: $@"
	mkdir -p $(BUILD_DIR)
	$(CC) $*/test_$*.c -o $@ -L. -isystem $* $(NIX_CFLAGS_COMPILE) $(DEPS)
endif

# Build mock static libraries
$(BUILD_DIR)/libmock$(PROJECT_NAME)_%.a: NIX_CFLAGS_COMPILE += $(MOCK_FLAGS)
$(BUILD_DIR)/libmock$(PROJECT_NAME)_%.a:
	echo "Building Mock Static Library: $@"
	mkdir -p $(BUILD_DIR)
	$(CC) -c $*/libmock$(PROJECT_NAME)_$*.c -o $(subst .a,.o,$@) -isystem $* $(NIX_CFLAGS_COMPILE) -fPIC
	ar r $@ $(subst .a,.o,$@) >/dev/null 2>&1

# Build mock shared libraries
$(BUILD_DIR)/libmock$(PROJECT_NAME)_%.so: NIX_CFLAGS_COMPILE += $(MOCK_FLAGS)
$(BUILD_DIR)/libmock$(PROJECT_NAME)_%.so: $(BUILD_DIR)/libmock$(PROJECT_NAME)_%.a
	echo "Building Mock Shared Library: $@"
	mkdir -p $(BUILD_DIR)
	$(CC) -shared -o $@ $(subst .so,.a,$@)

# Create the build directory if it does not exist
$(BUILD_DIR): $(BUILD_LIBS) $(BUILD_BINS) $(BUILD_MOCK_LIBS) $(BUILD_TEST_BINS)

# Allow overriding the target output directory
# For my purposes, this is overridden by the nix build system so that it can
# generate a proper output directory structure for the nngio derivation.
OUTPUT_DIR         ?= out
# Build output distribution for nix
$(OUTPUT_DIR): $(BUILD_DIR)
	mkdir -p $(OUTPUT_DIR)
	mkdir -p $(OUTPUT_DIR)/bin
	mv $(BUILD_BINS) $(OUTPUT_DIR)/bin
	mkdir -p $(OUTPUT_DIR)/bin/test
	mv $(BUILD_TEST_BINS) $(OUTPUT_DIR)/bin/test
	mkdir -p $(OUTPUT_DIR)/lib
	mv $(BUILD_LIBS) $(OUTPUT_DIR)/lib
	mv $(BUILD_MOCK_LIBS) $(OUTPUT_DIR)/lib
	mkdir -p $(OUTPUT_DIR)/include
	cp -r $(INCLUDE)/* $(OUTPUT_DIR)/include

.PHONY: all test format clean

# default target builds production binaries and libraries
all: $(BUILD_DIR)

# test will build mock libraries and binaries, then run tests with valgrind
test: $(BUILD_DIR)
	$(foreach test_bin,$(BUILD_TEST_BINS), \
	valgrind -s --leak-check=full \
	 --show-leak-kinds=all \
	 --track-origins=yes \
	 ./$(test_bin);)

# Format source code using clang-format
format:
	find . -iname '*.h' -o -iname '*.c' | xargs clang-format -i -style=google

# Clean up generated files and directories from local development
clean:
	-rm -fr $(BUILD_DIR) $(OUTPUT_DIR) **/*.o vgcore.* result

