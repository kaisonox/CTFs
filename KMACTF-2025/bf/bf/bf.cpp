#include <iostream>
#include <vector>
#include <stack>
#include <windows.h>
#include <cstdlib>

static const size_t TAPE_SIZE = 30000;
static std::vector<unsigned char> tape(TAPE_SIZE, 0);
static size_t ptr = 0;
static void* execMem = nullptr;
static std::vector<size_t> jumpMap;

// General VEH handler template: checks EXCEPTION_ILLEGAL_INSTRUCTION + operand
bool IsUd2Exception(PEXCEPTION_POINTERS info, unsigned char expectedOp) {
    if (info->ExceptionRecord->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION)
        return false;
    BYTE* ip = reinterpret_cast<BYTE*>(info->ContextRecord->Rip);
    unsigned char op = *(ip + 2);
    return op == expectedOp;
}

// Handler for '>' opcode
LONG WINAPI HandlerGt(PEXCEPTION_POINTERS info) {
    if (IsUd2Exception(info, '>')) {
        ptr = (ptr + 1) % TAPE_SIZE;
        info->ContextRecord->Rip += 3;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Handler for '<' opcode
LONG WINAPI HandlerLt(PEXCEPTION_POINTERS info) {
    if (IsUd2Exception(info, '<')) {
        ptr = ptr == 0 ? TAPE_SIZE - 1 : ptr - 1;
        info->ContextRecord->Rip += 3;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Handler for '+' opcode
LONG WINAPI HandlerPlus(PEXCEPTION_POINTERS info) {
    if (IsUd2Exception(info, '+')) {
        ++tape[ptr];
        info->ContextRecord->Rip += 3;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Handler for '-' opcode
LONG WINAPI HandlerMinus(PEXCEPTION_POINTERS info) {
    if (IsUd2Exception(info, '-')) {
        --tape[ptr];
        info->ContextRecord->Rip += 3;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Handler for '.' opcode
LONG WINAPI HandlerDot(PEXCEPTION_POINTERS info) {
    if (IsUd2Exception(info, '.')) {
        std::cout << static_cast<char>(tape[ptr]);
        info->ContextRecord->Rip += 3;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Handler for ',' opcode
LONG WINAPI HandlerComma(PEXCEPTION_POINTERS info) {
    if (IsUd2Exception(info, ',')) {
        int in = std::cin.get();
        tape[ptr] = (in == EOF ? 0 : static_cast<unsigned char>(in));
        info->ContextRecord->Rip += 3;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Handler for '[' opcode
LONG WINAPI HandlerLBracket(PEXCEPTION_POINTERS info) {
    if (IsUd2Exception(info, '[')) {
        if (tape[ptr] == 0) {
            BYTE* ip = reinterpret_cast<BYTE*>(info->ContextRecord->Rip);
            size_t idx = (ip - reinterpret_cast<BYTE*>(execMem)) / 3;
            size_t target = jumpMap[idx];
            info->ContextRecord->Rip = reinterpret_cast<ULONG_PTR>(execMem) + target * 3;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        info->ContextRecord->Rip += 3;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Handler for ']' opcode
LONG WINAPI HandlerRBracket(PEXCEPTION_POINTERS info) {
    if (IsUd2Exception(info, ']')) {
        if (tape[ptr] != 0) {
            BYTE* ip = reinterpret_cast<BYTE*>(info->ContextRecord->Rip);
            size_t idx = (ip - reinterpret_cast<BYTE*>(execMem)) / 3;
            size_t target = jumpMap[idx];
            info->ContextRecord->Rip = reinterpret_cast<ULONG_PTR>(execMem) + target * 3;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        info->ContextRecord->Rip += 3;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Fallback: skip unknown opcode
LONG WINAPI HandlerDefault(PEXCEPTION_POINTERS info) {
    if (info->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
        info->ContextRecord->Rip += 3;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main() {
    const std::string code = R"(-[--->+<]>-.[---->+++++<]>-.+.++++++++++.+[---->+<]>+++.-[--->++<]>-.++++++++++.+[---->+<]>+++.[-->+++++++<]>.++.-------------.[--->+<]>---..+++++.-[---->+<]>++.+[->+++<]>.++++++++++++..---.[-->+<]>--------.)";

    // Build jump map
    jumpMap.resize(code.size());
    std::stack<size_t> st;
    for (size_t i = 0; i < code.size(); ++i) {
        if (code[i] == '[') st.push(i);
        else if (code[i] == ']') {
            if (st.empty()) return EXIT_FAILURE;
            size_t open = st.top(); st.pop();
            jumpMap[open] = i;
            jumpMap[i] = open;
        }
    }

    // Assemble code blob
    std::vector<unsigned char> blob;
    blob.reserve(code.size() * 3 + 1);
    for (unsigned char c : code) {
        blob.push_back(0x0F);
        blob.push_back(0x0B);
        blob.push_back(c);
    }
    blob.push_back(0xC3);

    execMem = VirtualAlloc(nullptr, blob.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) return EXIT_FAILURE;
    memcpy(execMem, blob.data(), blob.size());

    // Register one handler per opcode (order matters)
    AddVectoredExceptionHandler(1, HandlerGt);
    AddVectoredExceptionHandler(1, HandlerLt);
    AddVectoredExceptionHandler(1, HandlerPlus);
    AddVectoredExceptionHandler(1, HandlerMinus);
    AddVectoredExceptionHandler(1, HandlerDot);
    AddVectoredExceptionHandler(1, HandlerComma);
    AddVectoredExceptionHandler(1, HandlerLBracket);
    AddVectoredExceptionHandler(1, HandlerRBracket);
    AddVectoredExceptionHandler(0, HandlerDefault);

    // Execute the VEH-driven VM
    reinterpret_cast<void(*)()>(execMem)();

    VirtualFree(execMem, 0, MEM_RELEASE);
    return 0;
}
