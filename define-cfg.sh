#!/bin/sh

$ make defconfig

$ echo CONFIG_USER_NS=y >> .config
$ echo CONFIG_USERFAULTFD=y >> .config

$ echo CONFIG_GDB_SCRIPTS=y >> .config
$ echo CONFIG_FRAME_POINTER=y >> .config
$ echo CONFIG_KGDB=y >> .config
$ echo CONFIG_KGDB_SERIAL_CONSOLE=y >> .config
$ echo CONFIG_KDB_KEYBOARD=y >> .config

$ < /boot/config-5.3.0-46-generic grep _FB_ >> .config

$ < /boot/config-5.3.0-46-generic grep _VIRTIO >> .config

$ sed -i 's/=m$/=y/' .config
$ make olddefconfig
