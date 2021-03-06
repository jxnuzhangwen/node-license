# This file is generated by gyp; do not edit.

TOOLSET := target
TARGET := licence
DEFS_Debug := \
	'-D_LARGEFILE_SOURCE' \
	'-D_FILE_OFFSET_BITS=64' \
	'-DBUILDING_NODE_EXTENSION' \
	'-DDEBUG' \
	'-D_DEBUG'

# Flags passed to all source files.
CFLAGS_Debug := \
	-Wall \
	-Wextra \
	-Wno-unused-parameter \
	-pthread \
	-m32 \
	-g \
	-O0

# Flags passed to only C files.
CFLAGS_C_Debug :=

# Flags passed to only C++ files.
CFLAGS_CC_Debug := \
	-fno-rtti \
	-fno-exceptions

INCS_Debug := \
	-I/home/zhangwen/.node-gyp/0.10.8/src \
	-I/home/zhangwen/.node-gyp/0.10.8/deps/uv/include \
	-I/home/zhangwen/.node-gyp/0.10.8/deps/v8/include \
	-I/home/zhangwen/.node-gyp/0.10.8/deps/openssl/openssl/include

DEFS_Release := \
	'-D_LARGEFILE_SOURCE' \
	'-D_FILE_OFFSET_BITS=64' \
	'-DBUILDING_NODE_EXTENSION'

# Flags passed to all source files.
CFLAGS_Release := \
	-Wall \
	-Wextra \
	-Wno-unused-parameter \
	-pthread \
	-m32 \
	-O2 \
	-fno-strict-aliasing \
	-fno-tree-vrp

# Flags passed to only C files.
CFLAGS_C_Release :=

# Flags passed to only C++ files.
CFLAGS_CC_Release := \
	-fno-rtti \
	-fno-exceptions

INCS_Release := \
	-I/home/zhangwen/.node-gyp/0.10.8/src \
	-I/home/zhangwen/.node-gyp/0.10.8/deps/uv/include \
	-I/home/zhangwen/.node-gyp/0.10.8/deps/v8/include \
	-I/home/zhangwen/.node-gyp/0.10.8/deps/openssl/openssl/include

OBJS := \
	$(obj).target/$(TARGET)/src/licence.o

# Add to the list of files we specially track dependencies for.
all_deps += $(OBJS)

# CFLAGS et al overrides must be target-local.
# See "Target-specific Variable Values" in the GNU Make manual.
$(OBJS): TOOLSET := $(TOOLSET)
$(OBJS): GYP_CFLAGS := $(DEFS_$(BUILDTYPE)) $(INCS_$(BUILDTYPE))  $(CFLAGS_$(BUILDTYPE)) $(CFLAGS_C_$(BUILDTYPE))
$(OBJS): GYP_CXXFLAGS := $(DEFS_$(BUILDTYPE)) $(INCS_$(BUILDTYPE))  $(CFLAGS_$(BUILDTYPE)) $(CFLAGS_CC_$(BUILDTYPE))

# Suffix rules, putting all outputs into $(obj).

$(obj).$(TOOLSET)/$(TARGET)/%.o: $(srcdir)/%.cc FORCE_DO_CMD
	@$(call do_cmd,cxx,1)

# Try building from generated source, too.

$(obj).$(TOOLSET)/$(TARGET)/%.o: $(obj).$(TOOLSET)/%.cc FORCE_DO_CMD
	@$(call do_cmd,cxx,1)

$(obj).$(TOOLSET)/$(TARGET)/%.o: $(obj)/%.cc FORCE_DO_CMD
	@$(call do_cmd,cxx,1)

# End of this set of suffix rules
### Rules for final target.
LDFLAGS_Debug := \
	-pthread \
	-rdynamic \
	-m32

LDFLAGS_Release := \
	-pthread \
	-rdynamic \
	-m32

LIBS :=

$(obj).target/licence.node: GYP_LDFLAGS := $(LDFLAGS_$(BUILDTYPE))
$(obj).target/licence.node: LIBS := $(LIBS)
$(obj).target/licence.node: TOOLSET := $(TOOLSET)
$(obj).target/licence.node: $(OBJS) FORCE_DO_CMD
	$(call do_cmd,solink_module)

all_deps += $(obj).target/licence.node
# Add target alias
.PHONY: licence
licence: $(builddir)/licence.node

# Copy this to the executable output path.
$(builddir)/licence.node: TOOLSET := $(TOOLSET)
$(builddir)/licence.node: $(obj).target/licence.node FORCE_DO_CMD
	$(call do_cmd,copy)

all_deps += $(builddir)/licence.node
# Short alias for building this executable.
.PHONY: licence.node
licence.node: $(obj).target/licence.node $(builddir)/licence.node

# Add executable to "all" target.
.PHONY: all
all: $(builddir)/licence.node

