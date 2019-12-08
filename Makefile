

CFLAGS += -O2 -DLINUX -D_GNU_SOURCE -Wall -DDEBUG

CLDFLAGS += -L/home/kanghua/src/trunk/staging_dir/target-mips_r2_uClibc-0.9.33.2/usr/lib  -L/home/kanghua/src/trunk/staging_dir/target-mips_r2_uClibc-0.9.33.2/usr/lib/

APP_BINARY =  p2p_action

all: $(APP_BINARY)

$(APP_BINARY): p2p_action.o 
	$(CC) $(CFLAGS) $^ $(CLDFLAGS) -o $@
clean:
	rm -rf *.o
	rm -rf $(APP_BINARY)
