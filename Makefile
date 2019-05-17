CC=gcc
CFLAGS=-Wall -Werror -O0 -g -pedantic -std=gnu99 -DSDP_EXTRACTOR_VERSION=\""$(SDP_EXTRACTOR_VERSION)"\"
APP=sdp_extractor
LIB_OBJS=sdp_field.o sdp_stream.o sdp_parser.o smpte2110_sdp_parser.o
APP_OBJS=util.o sdp_extractor.o sdp_extractor_app.o
SDP_LIB=libsdp.a

SDP_EXTRACTOR_VERSION:=$(shell git describe --dirty --long | sed 's/\([[:digit:]]\+\)\.\([[:digit:]]\+\)-\([[:digit:]]\+\)-g\(.*\)/\1.\2.\3 (git hash: \4)/g')

%.o: %.c
	$(CC) -o $@ $(CFLAGS) -c $<

.PHONY: all clean cleanall

all: $(APP)

$(APP): $(APP_OBJS) $(SDP_LIB)
	$(CC) -o $@ $^

$(SDP_LIB): $(LIB_OBJS)
	$(AR) -r $@ $^

clean:
	@echo "removing executables"
	@rm -f $(APP)
	@echo "removing object files"
	@rm -f *.o *.a

cleanall: clean
	@echo "removing pre compilation files"
	@rm -f *_pre.c
	@echo "removing tag file"
	@rm -f tags

