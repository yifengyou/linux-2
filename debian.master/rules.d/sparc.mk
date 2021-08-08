build_arch	= sparc64
header_arch	= $(build_arch)
asm_link	= $(build_arch)
defconfig	= defconfig
flavours	= sparc64 sparc64-smp
build_image	= image
kernel_file     = arch/sparc/boot/image
install_file	= vmlinuz
compress_file	= Yes

loader		= silo

skipdbg		= true
no_dumpfile	= true
skipabi		= true
skipmodule	= true

family=ports
