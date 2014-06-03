CC_CMD=/usr/bin/gcc -fpic -DNET_SSL -D_REENTRANT -DLINUX
LD_SHAREDCMD=/usr/bin/gcc -shared -Wl,-rpath .

all:
prepare:

NS_HOME=/usr/apps/netscape
INCLUDEDIR=$(NS_HOME)/plugins/include
EXTRA_LDDEFINES=-lssl


OBJS = ocsp.o

INCLUDE_FLAGS=-I$(INCLUDEDIR) -I$(INCLUDEDIR)/base -I$(INCLUDEDIR)/frame -I$(INCLUDEDIR)/nspr
COMMON_DEFS=-DMCC_HTTPD -DXP_UNIX -DSPAPI20


all: va-ocsp.so


va-ocsp.so: $(OBJS)
	$(MAKE) prepare
	$(LD_SHAREDCMD) $(OBJS) -o ocsp.so $(EXTRA_LDDEFINES) 

.c.o:
	$(CC_CMD) -D_BUILD_NSAPI_ $(COMMON_DEFS) $(INCLUDE_FLAGS) -c $< 

clean:
	rm $(OBJS) va-ocsp.so $(EXTRA_CLEAN)
