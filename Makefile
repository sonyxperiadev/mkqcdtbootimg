include libfdt/Makefile.libfdt

SRC_FILES := mkqcdtbootimg.c $(addprefix libfdt/,$(LIBFDT_SRCS))
OBJ_FILES := $(SRC_FILES:%.c=%.o)
LDFLAGS := -lcrypto
CFLAGS := -Ilibfdt -Wall
MODULE := mkqcdtbootimg

all: $(MODULE)

$(MODULE): $(OBJ_FILES)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	$(RM) $(OBJ_FILES) $(MODULE)
