build_arch	= x86_64
header_arch	= $(build_arch)
asm_link	= x86
defconfig	= defconfig
flavours	= generic server preempt
build_image	= bzImage
kernel_file	= arch/$(build_arch)/boot/bzImage
install_file	= vmlinuz

server_sub	= virtual

loader		= grub
