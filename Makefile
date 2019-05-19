vpath %.c src
vpath %.h src
ALL_LIBS := $(shell ldconfig -p)
MYSQL_LIB = mysqlclient
ifneq ($(findstring mariadbclient,$(ALL_LIBS)),)
MYSQL_LIB_DIR = $(shell ldconfig -p | grep mariadbclient.so | tail -1 | awk '{print $$4}' | xargs dirname)
MYSQL_LIB = mariadbclient
else ifneq ($(findstring mysqlclient,$(ALL_LIBS)),)
MYSQL_LIB_DIR = $(shell ldconfig -p | grep mysqlclient.so | tail -1 | awk '{print $$4}' | xargs dirname)
else
MYSQL_LIB_DIR = /usr/lib
endif

ifeq ($(VERSION),)
VERSION=0.0
endif

RH = $(shell if [ -f /etc/redhat-release ]; then echo "yes"; else echo "no"; fi;)
ifneq ($(findstring yes,$(RH)),)
SOURCE_TYPE = _BSD_SOURCE
else
SOURCE_TYPE = _DEFAULT_SOURCE
endif

PWD = $(shell pwd)
LIBS = -lpthread -levent -lcrypto
SRVLIBS = -L$(MYSQL_LIB_DIR) -l$(MYSQL_LIB) $(LIBS)
CCFLAGS = -D$(SOURCE_TYPE) -D_XOPEN_SOURCE -std=c99 -Wall -I./src
SRCS = common.c buffer.c connect.c crypto.c srp.c network.c config.c access_control.c
NODESRCS = node.c $(SRCS)
SRVSRCS = dbpool.c server.c $(SRCS)

all: clean srpn srps

release: clean release-srpn release-srps

pkg-release: clean alpine-docker centos-7-rpm ubuntu-1604-deb ubuntu-1804-deb release

srpn: $(NODESRCS)
	gcc $(CCFLAGS) -D_NODE $^ srpn.c $(LIBS) -g -o srpn

srps: $(SRVSRCS)
	gcc $(CCFLAGS) -D_SERVER $^ srps.c $(SRVLIBS) -g -o srps

release-srpn: $(NODESRCS)
	gcc $(CCFLAGS) -D_NODE $^ srpn.c $(LIBS) -o srpn

release-srps: $(SRVSRCS)
	gcc $(CCFLAGS) -D_SERVER $^ srps.c $(SRVLIBS) -o srps

%-image:
	make -C scripts/ -f docker-image-makefile TGT=$*

%-docker: %-image
	make -C scripts/$* TGT=alpine VERSION=$(VERSION)

%-rpm: %-image
	@docker run --rm -v $(PWD):/opt srp-$*-dev make -C /opt/scripts/$* VERSION=$(VERSION)

%-deb: %-image
	@docker run --rm -v $(PWD):/opt srp-$*-dev make -C /opt/scripts -f deb-makefile TGT=$* VERSION=$(VERSION)

%-bin: %-image
	@docker run --rm -v $(PWD):/opt srp-$*-dev make -C /opt VERSION=$(VERSION)

clean: srpn-clean srps-clean

srpn-clean:
	@-rm -rf srpn

srps-clean:
	@-rm -rf srps
