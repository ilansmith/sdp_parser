SAFELIB=safestringlib
CC=gcc
CFLAGS=-Wall -Werror -O0 -g -I$(SAFELIB)
LFLAGS=-lsafestring -L$(SAFELIB)
APP=test
OBJS=sdp_stream.o sdp_parser.o smpte2110_sdp_parser.o test.o

%.o: %.c
	$(CC) -o $@ $(CFLAGS) -c $<

.PHONY: all clean cleanall

all: $(APP)

$(APP): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LFLAGS)

clean:
	@echo "removing executables"
	@rm -f $(APP)
	@echo "removing object files"
	@rm -f *.o

cleanall: clean
	@echo "removing pre compilation files"
	@rm -f *_pre.c
	@echo "removing tag file"
	@rm -f tags

