#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

typedef struct {
	char *name;
	uint32_t NID;
} vita_imports_stub_t;

extern "C" vita_imports_stub_t *vita_imports_stub_new(const char *name, uint32_t NID);
extern "C" void vita_imports_stub_free(vita_imports_stub_t *stub);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();
    const char* name = str.c_str();
    uint32_t NID = provider.ConsumeIntegral<uint32_t>();

    vita_imports_stub_t* stub = vita_imports_stub_new(name, NID);
    vita_imports_stub_free(stub);

    return 0;
}