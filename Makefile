CXXFLAGS ?= -std=c++17
arpscan: util.o main.o
	$(CXX) $^ -o $@ $(CXXFLAGS)

%.cpp: types.h

%.o: %.cpp
	$(CXX) -c $< $(CXXFLAGS)

clean:
	$(RM) *.o arpscan
