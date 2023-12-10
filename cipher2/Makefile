CXX = g++
CXXFLAGS = -Wall -std=c++14
LDFLAGS = -lcryptopp

SOURCES = main.cpp
OBJECTS = $(SOURCES:.cpp=.o)
EXECUTABLE = file_crypt

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

.PHONY: clean

clean:
	rm -f $(OBJECTS) $(EXECUTABLE)
