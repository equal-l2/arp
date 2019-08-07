UNAME = $(shell uname -s)
CXXFLAGS += -std=c++17

# On SunOS, libsocket is required for getifaddrs()
ifeq ($(UNAME),SunOS)
    LDFLAGS += -lsocket
endif

arpscan: util.o main.o
	$(CXX) $^ -o $@ $(CXXFLAGS) $(LDFLAGS)

%.cpp: types.h

%.o: %.cpp
	$(CXX) -c $< $(CXXFLAGS)

clean:
	$(RM) *.o arpscan
