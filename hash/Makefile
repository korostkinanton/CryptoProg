CC = g++
CFLAGS = -Wall -Wextra -std=c++17
LDFLAGS = -lcryptopp
EXEC = main
SRCS = main.cpp 
OBJS = $(SRCS:.cpp=.o)

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< #-o $@
	
clean:
	rm -f $(OBJS) $(EXEC)
