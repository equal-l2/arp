CXXFLAGS ?= -std=c++17
arpscan: bsd.o main.o
	$(CXX) $^ -o $@ $(CXXFLAGS)

%.cpp: types.h

%.o: %.cpp
	$(CXX) -c $< $(CXXFLAGS)
