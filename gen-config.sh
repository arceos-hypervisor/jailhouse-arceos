# Generate system configuration
sudo python3 ./tools/jailhouse-config-create --mem-hv 4G ./configs/x86/qemu-arceos.c
sudo chown $(whoami) ./configs/x86/qemu-arceos.c
echo "Created config file at './configs/x86/qemu-arceos.c'"

# # Extract kernel command line
# cmdline=$(cat ./configs/x86/qemu-arceos.c | grep memmap | tr -d " \*" | sed 's/\$/\\\\\\\\\\$/g')

# echo "Get cmdline: $cmdline, see '/etc/default/grub'"

# Update grub config
# cmdline=$(echo $cmdline | sed 's/\\/\\\\/g')
cmdline='memmap=0x100000000\\\\\\$0x100000000'
sudo sed -i "s/GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=$cmdline/" /etc/default/grub
echo "Appended kernel cmdline: $cmdline, see '/etc/default/grub'"

echo "You should reboot if it's your first time to update it..."
