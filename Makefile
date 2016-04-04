OBJS += buttons.o
OBJS += layout.o
OBJS += oled.o
OBJS += rng.o
OBJS += serialno.o
OBJS += setup.o
OBJS += util.o
OBJS += memory.o
OBJS += gen/bitmaps.o
OBJS += gen/fonts.o

libtrezor.a: $(OBJS)
	ar rcs libtrezor.a $(OBJS)

include Makefile.include
