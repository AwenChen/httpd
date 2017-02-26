#
# httpd Makefile
#

PWD_PATH   = $(shell pwd)
SRC        = $(PWD_PATH)/src
OBJ        = $(PWD_PATH)/obj
EXE        = $(PWD_PATH)/httpd

OBJS       = $(OBJ)/httpd.o
OBJS      += $(OBJ)/utils.o
OBJS      += $(OBJ)/base64.o

CCFLAGS    = -Wall -I$(SRC)

CCLIBS     = -lpthread

all: prepare link

prepare:
	if [ ! -d $(OBJ) ];then \
	   mkdir -p $(OBJ); \
	fi

link: $(OBJS)
	gcc -o $(EXE) $(OBJS) $(CCFLAGS) $(CCLIBS)

$(OBJ)/httpd.o: $(SRC)/httpd.c $(SRC)/base64.h $(SRC)/utils.h $(SRC)/common.h
	gcc $(CCFLAGS) -o $@ -c $< || exit 1

$(OBJ)/utils.o: $(SRC)/utils.c $(SRC)/utils.h $(SRC)/common.h
	gcc $(CCFLAGS) -o $@ -c $< || exit 1

$(OBJ)/base64.o: $(SRC)/base64.c $(SRC)/base64.h
	gcc $(CCFLAGS) -o $@ -c $< || exit 1


clean:
	-rm -rf $(OBJ) $(EXE)

