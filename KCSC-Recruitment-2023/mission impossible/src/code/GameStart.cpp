

#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>
#include <fstream>
#include <filesystem>

// find winrar path
std::string FindWinRARPath()
{
    const std::vector<std::string> possiblePaths = {
        "C:\\Program Files\\WinRAR\\WinRAR.exe",
        "C:\\Program Files (x86)\\WinRAR\\WinRAR.exe"
    };

    for (const auto &path : possiblePaths)
    {
        DWORD fileAttr = GetFileAttributesA(path.c_str());
        if (fileAttr != INVALID_FILE_ATTRIBUTES && !(fileAttr & FILE_ATTRIBUTE_DIRECTORY))
        {
            return path;
        }
    }

    return "";
}

bool ModifyResourceSignature(int is_restore)
{
    // read the file resource
    std::string resource_path = "./resources";
    std::fstream file(resource_path, std::ios::binary | std::ios::in | std::ios::out);

    if (!file)
    {
        std::cerr << "Unable to open file: " << resource_path << std::endl;
        return false;
    }
    char bytes[4] = {0x00};
    if (is_restore)
    {
        // check if the the signature is sonx
        file.read(bytes, sizeof(bytes));
        if (bytes[0] != 0x73 || bytes[1] != 0x6f || bytes[2] != 0x6e || bytes[3] != 0x78)
        {
            std::cerr << "Unknown resource signature!" << std::endl;
            return false;
        }

        // rar!
        bytes[0] = 0x52;
        bytes[1] = 0x61;
        bytes[2] = 0x72;
        bytes[3] = 0x21;
    }
    else
    {
        // sonx
        bytes[0] = 0x73;
        bytes[1] = 0x6f;
        bytes[2] = 0x6e;
        bytes[3] = 0x78;
    }

    file.seekp(0, std::ios::beg);
    file.write(bytes, sizeof(bytes));

    if (!file)
    {
        std::cerr << "Unable to write file: " << resource_path << std::endl;
        return false;
    }
    file.close();
    return true;
}

bool RunHiddenCommand(const std::string &cmd)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // This flag hides the window
    ZeroMemory(&pi, sizeof(pi));

    // Create a process for the command
    if (!CreateProcessA(
            NULL,               // No module name (use command line)
            (LPSTR)cmd.c_str(), // Command line
            NULL,               // Process handle not inheritable
            NULL,               // Thread handle not inheritable
            FALSE,              // Set handle inheritance to FALSE
            0,                  // No creation flags
            NULL,               // Use parent's environment block
            NULL,               // Use parent's starting directory
            &si,                // Pointer to STARTUPINFO structure
            &pi                 // Pointer to PROCESS_INFORMATION structure
            ))
    {
        std::cerr << "CreateProcess failed (" << GetLastError() << ").\n";
        return false;
    }

    // Wait until child process exits
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Close process and thread handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return true;
}

bool ExtractResource(const std::string &winrar_path)
{
    std::string command = "\"" + winrar_path + "\" x -ierr ./resources .";
    if (!RunHiddenCommand(command))
    {
        std::cerr << "Extract resource failed!" << std::endl;
        return false;
    }
    return true;
}

void DeleteFolders()
{
    const std::vector<std::string> possiblePaths = {
        "./audio",
        "./config",
        "./graphics",
    };

    for (const auto &path : possiblePaths)
    {
        try
        {
            std::filesystem::remove_all(path);
        }
        catch (std::filesystem::filesystem_error &e)
        {
            std::cout << "Error deleting folder: " << e.what() << std::endl;
        }
    }
}

int main()
{
    // find winrar path
    std::string winrar_path = FindWinRARPath();
    if (winrar_path == "")
    {
        std::cout << "Can't find WinRAR path!" << std::endl;
        return 0;
    }

    // restore resource signature
    if (!ModifyResourceSignature(1))
    {
        std::cout << "Restore resource signature failed!" << std::endl;
        return 0;
    }

    // extract resource
    if (!ExtractResource(winrar_path))
    {
        std::cout << "Extract resource failed!" << std::endl;
        return 0;
    }

    


    DeleteFolders();
    ModifyResourceSignature(0);

    return 0;
}
