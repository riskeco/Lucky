#!/bin/sh

cp arch/x86/boot/bzImage /boot/vmlinuz-4.15.0-lucky

update-grub

main_entry=$( grep submenu /boot/grub/grub.cfg | sed "s#.*'\([^']*\)' {#\1#" )

kernel_entry=$( grep -- "-lucky'" /boot/grub/grub.cfg | sed "s#.*'\([^']*\)' {#\1#" )

sed -i "s/^GRUB_DEFAULT=.*$/GRUB_DEFAULT=\"$main_entry>$kernel_entry\"/" /etc/default/grub

update-grub

truncate -s0 /var/log/syslog
