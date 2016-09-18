CC=g++
RM=rm -f

TARGET=t
SRCS=$(wildcard *.cpp)
OBJS=$(SRCS:.cpp=.o)

override CFLAGS+=-Wall -std=c++11 -O2 -g
LFLAGS=

INCLUDES=
LIBDIRS=
LIBS=-lssl -lcrypto

all: clean $(TARGET)

clean:
	$(RM) $(OBJS) $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LFLAGS) $(LIBDIRS) $^ -o $@ $(LIBS)

$(OBJS): $(SRCS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $^
