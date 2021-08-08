build_arch	= arm
header_arch	= arm
asm_link	= arm
defconfig	= defconfig
flavours	= versatile
build_image	= zImage
kernel_file	= arch/$(build_arch)/boot/zImage
install_file	= vmlinuz
no_dumpfile = true
# ARM is not a supported architecture in perf userspace
do_tools	= false

loader		= grub
