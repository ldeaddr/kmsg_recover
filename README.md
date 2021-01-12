# kmsg\_recover - recover past kernel logs from RAM

This is potentially useful as a debug tool, when the last pre-crash portions
of the kernel log don't get written to disk.
On the next boot, kmsg\_recover will read the physical memory where
`__log_buf` was previously located, run it through strings and save the
physical address of the current `__log_buf` to be used on the next boot.

Kdump is a better option for this, however it might not do anything in case of a hang.

# Installing
	# cp kmsg_recover.cfg /etc/default/grub.d/
	# cp kmsg_recover.service /etc/systemd/system/
	# cp kmsg_recover.sh /usr/sbin/
	# dkms install src
	# systemctl enable kmsg_recover
	# systemctl start kmsg_recover

Starting the service fails on the first time because there is no past
`__log_buf` address to use and dump. Writing this sentence was quicker than
fixing it.

# Issues
- This has only been tested on Linux 5.10.4
- The module assumes the `__log_buf` area is contiguous in physical memory.
I don't know when/if this assumption is false.
- No synchronization/locking. Run only one instance of `kmsg_recover.sh` at a time.
- Probably more unknown unknowns considering I know only enough kernel
programming to shoot myself in the foot.
