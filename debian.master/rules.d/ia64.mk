build_arch	= ia64
header_arch	= $(build_arch)
asm_link	= $(build_arch)
defconfig	= defconfig
flavours	= ia64
build_image	= vmlinux
kernel_file	= $(build_image)
install_file	= vmlinuz
compress_file	= yes

loader		= elilo

skipdbg		= true
no_dumpfile	= true
skipabi		= true
skipmodule	= true

# XXX: ia64 libelf-dev/binutils-dev dependancy does not supply libraries?!?
do_tools	= false

family=ports
