define run_qemu_x86
	$(call xbuild_action,QEMU,$@) \
		$(SRCDIR)/arch/x86/tools/qemu.sh "$(OBJCOPY)"
endef

.PHONY: qemu
qemu: x15
	$(call run_qemu_x86)

ifeq ($(shell uname -m),x86_64)
  KCONFIG_DEFCONFIG := amd64_defconfig
else
  KCONFIG_DEFCONFIG := i386_defconfig
endif

define ARCH_HELP
	@printf '  qemu                     - Run kernel in QEMU\n'
endef

# Prevent GCC from generating any FP code by mistake.
XBUILD_CFLAGS += -mno-sse -mno-mmx -mno-sse2 -mno-3dnow
XBUILD_CFLAGS += $(call cc-option,-mno-avx,)

XBUILD_LDFLAGS += -Wl,-z,max-page-size=4096 -Wl,-z,common-page-size=4096

ifeq ($(CONFIG_X86_32),y)
        biarch := $(call cc-option,-m32)
        XBUILD_CPPFLAGS += -m32
else
        biarch := -m64
        XBUILD_CPPFLAGS += -m64
        XBUILD_CFLAGS += -mcmodel=kernel
endif

x15_SOURCES-y += \
        arch/x86/machine/acpi.c \
        arch/x86/machine/atcons.c \
        arch/x86/machine/atkbd.c \
        arch/x86/machine/biosmem.c \
        arch/x86/machine/boot_asm.S \
        arch/x86/machine/boot.c \
        arch/x86/machine/cga.c \
        arch/x86/machine/cpu_asm.S \
        arch/x86/machine/cpu.c \
        arch/x86/machine/ioapic.c \
        arch/x86/machine/lapic.c \
        arch/x86/machine/pic.c \
        arch/x86/machine/pit.c \
        arch/x86/machine/pmap.c \
        arch/x86/machine/ssp.c \
        arch/x86/machine/string.c \
        arch/x86/machine/tcb_asm.S \
        arch/x86/machine/tcb.c \
        arch/x86/machine/uart.c

x15_SOURCES-$(CONFIG_X86_PMU_AMD) += arch/x86/machine/pmu_amd.c
x15_SOURCES-$(CONFIG_X86_PMU_INTEL) += arch/x86/machine/pmu_intel.c
