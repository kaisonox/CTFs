

#include <iostream>
#include <dlfcn.h>    // For dynamic loading
#include <string>
#include <fstream>
#include <algorithm> 
#include <unistd.h>

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines


// Define a function pointer type for hash
typedef std::string (*hash_func)(const unsigned char*);


std::string libPath = "./hash.so";
std::string target = "b99aff88d8e71fba4bce610f4d3cbc8d";
BYTE encFlag[] = {65, 23, 65, 0, 17, 110, 64, 91, 89, 71, 66, 66, 19, 16, 83, 59, 2, 92, 66, 106, 66, 20, 85, 12, 58, 20, 86, 90, 13, 3, 8, 5};

std::string getProcessExecutablePath() {
	char buf[256];
	ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf));
	return std::string(buf, (len > 0) ? len : 0);
}


int numberOfAttemptsRemaining() {
    std::fstream file;
    int offset = 0x409B;
    // open file for reading and writing
    file.open(libPath, std::ios::in | std::ios::out | std::ios::binary);

    // move to offset 0x4098
    file.seekg(offset, std::ios::beg);
    // read a byte
    BYTE byte;
    file.read((char*)&byte, 1);
    int remaining = 3 - byte;

    // increase byte at offset 0x4098 by 1
    file.seekg(offset, std::ios::beg);
    byte++;
    file.write((char*)&byte, 1);
    file.close();

    return remaining;
}


int main() {
	std::string input;
    // Load the shared library
    
    void* handle = dlopen(libPath.c_str(), RTLD_LAZY);
    if (!handle) {
        std::cerr << "Cannot load library: " << dlerror() << std::endl;
        return 1;
    }

    // Reset errors
    dlerror();

    // Load the symbol (function)
    hash_func hash = (hash_func) dlsym(handle, "hash");
    const char* dlsym_error = dlerror();
    if (dlsym_error) {
        std::cerr << "Cannot load symbol 'hash': " << dlsym_error << std::endl;
        dlclose(handle);
        return 1;
    }
    
    int remaining = numberOfAttemptsRemaining();
    if (remaining == 0) {
        std::cout << "No more attempts remaining! Bye!" << std::endl;
        // delete file
        if (remove(libPath.c_str()) != 0) {
            std::cout << "Error deleting lib file!" << std::endl;
            return 1;
        }
        if (remove(getProcessExecutablePath().c_str()) != 0) {
            std::cout << "Error deleting exec file!" << std::endl;
            return 1;
        }
        return 0;
    }
    std::cout << "Attempts remaining: " << remaining << std::endl;
    std::cout << "Enter password: ";
    std::cin >> input;

    std::string hashed = hash(reinterpret_cast<const unsigned char*>(input.c_str()));
    if (hashed == target) {
    	std::reverse(input.begin(), input.end());
    	hashed = hash(reinterpret_cast<const unsigned char*>(input.c_str()));
		size_t len = sizeof(encFlag);
		
		for (size_t i = 0; i < len; ++i) {
		    encFlag[i] ^= hashed[i % len];
		}
		
		std::cout << "KCSC{";
		for (size_t i = 0; i < len; ++i) {
    		std::cout << static_cast<char>(encFlag[i]);
		}
		std::cout << "}" << std::endl;
    
    }
    else
    	std::cout << "Wrong password bro ~~~" << std::endl;

    // Close the library
    dlclose(handle);
    
    return 0;
}
