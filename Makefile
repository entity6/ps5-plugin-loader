ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF     := ploader.elf
SOURCES := main.cpp
CXXFLAGS += -std=c++17 -Wall -Wextra -O2 -g
LDFLAGS  +=

all: $(ELF)

$(ELF): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(ELF)
