#!/bin/bash -p

STTY=$(stty -g)
stty intr ^-

TEMP="./tmp"
#chgrp ctf ${TEMP}
chmod 730 ${TEMP}

echo "-----------------------------------------------------------------------------"
echo "To ease your exploit development, a secret folder shared between the host and"
echo "the vm will be created. You can access it at /mnt/share within the vm, and at"
echo "${TEMP} in the host. The folder will be deleted afterwards."
echo "-----------------------------------------------------------------------------"
echo ""
#read -p "Press <Enter> to continue..."

/usr/bin/qemu-system-x86_64                  \
    -m 64M                                                            \
    -gdb tcp::3456	\
    -cpu kvm64                                                        \
    -kernel bzImage                                         \
    -nographic                                                        \
    -append 'console=ttyS0 loglevel=3 oops=panic panic=1 kaslr nopti' \
    -initrd initramfs.example.cpio                                  \
    -monitor /dev/null                                                \
    -fsdev local,id=exp1,path=${TEMP},security_model=mapped           \
    -device virtio-9p-pci,fsdev=exp1,mount_tag=ecsc

#rm -rf "${TEMP}" 2> /dev/null
stty "${STTY}"
