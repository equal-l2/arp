CXXFLAGS += -std=c++17

ifeq ($(shell uname -s), SunOS)
    LDFLAGS += -lsocket
endif

arpscan: util.o main.o
	$(CXX) $^ -o $@ $(CXXFLAGS) $(LDFLAGS)

%.cpp: types.h

%.o: %.cpp
	$(CXX) -c $< $(CXXFLAGS)

clean:
	$(RM) *.o arpscan
