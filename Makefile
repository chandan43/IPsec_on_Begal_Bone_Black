#obj-m := esp4.o
obj-m := esp.o

#CFLAGS_esp4.o := -DDEBUG

KDIR=/lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules 
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean 	 
