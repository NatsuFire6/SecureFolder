#define UNICODE
#define _UNICODE

#include <windows.h>
#include <bcrypt.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <winhttp.h>
#include "window_save_manager.h"

#include <array>
#include <filesystem>
#include <string>
#include <unordered_set>
#include <vector>

namespace
{
constexpr wchar_t kWindowClass[] = L"SecureFolderWindow";
constexpr UINT kOpenSelectedMessage = WM_APP + 1;
constexpr UINT kCreateVaultMessage = WM_APP + 2;
constexpr int kTimerId = 1;
constexpr int kOpenButton = 1001;
constexpr int kCreateButton = 1002;
constexpr int kSettingsButton = 1003;
constexpr int kLockButton = 1004;
constexpr int kAssociateButton = 1005;
constexpr int kTimeoutEdit = 1006;
constexpr int kSleepCheck = 1007;
constexpr int kShutdownCheck = 1008;
constexpr int kForceCheck = 1009;
constexpr int kSaveButton = 1010;
constexpr int kSelectButton = 1011;
constexpr wchar_t kVeraCryptVersion[] = L"1.26.29";
constexpr wchar_t kVeraCryptInstallerUrl[] =
    L"https://launchpad.net/veracrypt/trunk/1.26.29/+download/VeraCrypt_Setup_x64_1.26.29.msi";
constexpr wchar_t kVeraCryptInstallerSha256[] =
    L"5BA6426983123CFB92BC1F09BD888FDBC0F53F300D0D9C5DA52CE3AEE8D474F0";

struct Settings
{
    unsigned timeoutMinutes = 15;
    bool lockOnSleep = true;
    bool lockOnShutdown = true;
    bool forceUnmount = false;
};

HWND g_window = nullptr;
HWND g_status = nullptr;
HWND g_pathCaption = nullptr;
HWND g_pathLabel = nullptr;
HWND g_selectButton = nullptr;
HWND g_settingsCaption = nullptr;
HWND g_timeoutCaption = nullptr;
HWND g_settingsNote = nullptr;
HWND g_openButton = nullptr;
HWND g_createButton = nullptr;
HWND g_settingsButton = nullptr;
HWND g_lockButton = nullptr;
HWND g_associateButton = nullptr;
HWND g_timeoutEdit = nullptr;
HWND g_sleepCheck = nullptr;
HWND g_shutdownCheck = nullptr;
HWND g_forceCheck = nullptr;
HWND g_saveButton = nullptr;

std::wstring g_currentPath;
std::wstring g_createVaultDirectory;
std::wstring g_veraCryptPath;
Settings g_settings;
bool g_mounted = false;
bool g_mountPending = false;
bool g_settingsAuthentication = false;
bool g_keepOpenAfterAuthentication = false;
bool g_settingsUnlocked = false;
bool g_reauthenticationInProgress = false;
wchar_t g_driveLetter = L'\0';
ULONGLONG g_mountedAt = 0;
ULONGLONG g_mountStarted = 0;
HANDLE g_mountProcess = nullptr;

void SetStatus(const std::wstring& text);
void UpdateControls();

std::wstring Quote(const std::wstring& value)
{
    return L"\"" + value + L"\"";
}

bool IsDriveMounted(wchar_t letter)
{
    wchar_t root[] = L"X:\\";
    root[0] = letter;
    return GetDriveTypeW(root) != DRIVE_NO_ROOT_DIR;
}

std::wstring GetSettingsPath()
{
    if (!g_driveLetter)
        return {};
    std::wstring path;
    path.push_back(g_driveLetter);
    path += L":\\.securefolder-settings.ini";
    return path;
}

std::wstring GetRunningExecutable()
{
    std::vector<wchar_t> buffer(32768);
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size())
        return {};
    return std::wstring(buffer.data(), length);
}

bool FindVeraCrypt()
{
    if (!g_veraCryptPath.empty())
        return true;

    const wchar_t* candidates[] = {
        L"C:\\Program Files\\VeraCrypt\\VeraCrypt.exe",
        L"C:\\Program Files (x86)\\VeraCrypt\\VeraCrypt.exe"
    };
    for (const wchar_t* candidate : candidates)
    {
        if (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES)
        {
            g_veraCryptPath = candidate;
            return true;
        }
    }
    return false;
}

std::wstring FindVeraCryptFormat()
{
    if (!FindVeraCrypt())
        return {};
    const size_t separator = g_veraCryptPath.find_last_of(L"\\/");
    if (separator == std::wstring::npos)
        return {};
    const std::wstring formatPath = g_veraCryptPath.substr(0, separator + 1) + L"VeraCrypt Format.exe";
    return GetFileAttributesW(formatPath.c_str()) != INVALID_FILE_ATTRIBUTES ? formatPath : L"";
}

bool DownloadVeraCryptInstaller(std::wstring& installerPath)
{
    wchar_t tempDirectory[MAX_PATH]{};
    const DWORD tempLength = GetTempPathW(static_cast<DWORD>(std::size(tempDirectory)), tempDirectory);
    if (tempLength == 0 || tempLength >= std::size(tempDirectory))
        return false;

    wchar_t tempFile[MAX_PATH]{};
    if (GetTempFileNameW(tempDirectory, L"SFC", 0, tempFile) == 0)
        return false;
    installerPath = tempFile;

    URL_COMPONENTSW components{};
    components.dwStructSize = sizeof(components);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(kVeraCryptInstallerUrl, 0, 0, &components))
    {
        DeleteFileW(installerPath.c_str());
        return false;
    }

    const std::wstring host(components.lpszHostName, components.dwHostNameLength);
    const std::wstring path(components.lpszUrlPath, components.dwUrlPathLength);
    HINTERNET session = WinHttpOpen(L"SecureFolder/1.0",
                                    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET connection = session ? WinHttpConnect(session, host.c_str(), components.nPort, 0) : nullptr;
    HINTERNET request = connection
        ? WinHttpOpenRequest(connection, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES,
                             components.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0)
        : nullptr;

    bool downloaded = false;
    HANDLE file = INVALID_HANDLE_VALUE;
    if (request &&
        WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(request, nullptr))
    {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize,
                                WINHTTP_NO_HEADER_INDEX) && statusCode == 200)
        {
            file = CreateFileW(installerPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_TEMPORARY, nullptr);
            if (file != INVALID_HANDLE_VALUE)
            {
                std::array<unsigned char, 64 * 1024> buffer{};
                ULONGLONG totalBytes = 0;
                downloaded = true;
                for (;;)
                {
                    DWORD available = 0;
                    if (!WinHttpQueryDataAvailable(request, &available))
                    {
                        downloaded = false;
                        break;
                    }
                    if (available == 0)
                        break;

                    while (available > 0)
                    {
                        const DWORD toRead = (available > buffer.size())
                            ? static_cast<DWORD>(buffer.size()) : available;
                        DWORD bytesRead = 0;
                        if (!WinHttpReadData(request, buffer.data(), toRead, &bytesRead) || bytesRead == 0)
                        {
                            downloaded = false;
                            break;
                        }
                        totalBytes += bytesRead;
                        if (totalBytes > 100ULL * 1024ULL * 1024ULL)
                        {
                            downloaded = false;
                            break;
                        }
                        DWORD bytesWritten = 0;
                        if (!WriteFile(file, buffer.data(), bytesRead, &bytesWritten, nullptr) ||
                            bytesWritten != bytesRead)
                        {
                            downloaded = false;
                            break;
                        }
                        available -= bytesRead;
                    }
                    if (!downloaded)
                        break;
                }
                if (totalBytes == 0)
                    downloaded = false;
            }
        }
    }

    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (request)
        WinHttpCloseHandle(request);
    if (connection)
        WinHttpCloseHandle(connection);
    if (session)
        WinHttpCloseHandle(session);

    if (!downloaded)
    {
        DeleteFileW(installerPath.c_str());
        installerPath.clear();
    }
    return downloaded;
}

bool VerifyVeraCryptInstaller(const std::wstring& installerPath)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        return false;

    DWORD objectLength = 0;
    DWORD resultLength = 0;
    bool verified = false;
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength),
                          &resultLength, 0) >= 0)
    {
        std::vector<UCHAR> hashObject(objectLength);
        BCRYPT_HASH_HANDLE hash = nullptr;
        if (BCryptCreateHash(algorithm, &hash, hashObject.data(), objectLength,
                             nullptr, 0, 0) >= 0)
        {
            HANDLE file = CreateFileW(installerPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            bool readSucceeded = file != INVALID_HANDLE_VALUE;
            std::array<UCHAR, 64 * 1024> buffer{};
            while (readSucceeded)
            {
                DWORD bytesRead = 0;
                if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr))
                {
                    readSucceeded = false;
                    break;
                }
                if (bytesRead == 0)
                    break;
                if (BCryptHashData(hash, buffer.data(), bytesRead, 0) < 0)
                {
                    readSucceeded = false;
                    break;
                }
            }
            if (file != INVALID_HANDLE_VALUE)
                CloseHandle(file);

            std::array<UCHAR, 32> digest{};
            if (readSucceeded &&
                BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0)
            {
                constexpr wchar_t hex[] = L"0123456789ABCDEF";
                std::wstring actual;
                actual.reserve(digest.size() * 2);
                for (UCHAR byte : digest)
                {
                    actual.push_back(hex[byte >> 4]);
                    actual.push_back(hex[byte & 0x0F]);
                }
                verified = actual == kVeraCryptInstallerSha256;
            }
            BCryptDestroyHash(hash);
        }
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return verified;
}

bool InstallVeraCrypt()
{
    const std::wstring prompt =
        L"VeraCrypt n'est pas installé.\n\nSecureFolder va télécharger VeraCrypt " +
        std::wstring(kVeraCryptVersion) +
        L" (version 64 bits) depuis son distributeur officiel, vérifier l'intégrité du fichier, "
        L"puis lancer son programme d'installation. Une connexion Internet et votre accord à la "
        L"demande d'autorisation Windows (UAC) sont nécessaires.\n\nContinuer ?";
    const int answer = MessageBoxW(
        g_window, prompt.c_str(),
        L"Installation requise", MB_ICONINFORMATION | MB_YESNO | MB_DEFBUTTON2);
    if (answer != IDYES)
        return false;

    SetStatus(std::wstring(L"Téléchargement de VeraCrypt ") + kVeraCryptVersion + L"...");
    UpdateWindow(g_window);
    std::wstring installerPath;
    if (!DownloadVeraCryptInstaller(installerPath))
    {
        SetStatus(L"Échec du téléchargement de VeraCrypt.");
        MessageBoxW(g_window,
                    L"Le téléchargement de VeraCrypt a échoué. Vérifiez votre connexion Internet, puis réessayez.",
                    L"Téléchargement impossible", MB_ICONERROR | MB_OK);
        return false;
    }

    SetStatus(L"Vérification du fichier d'installation...");
    UpdateWindow(g_window);
    if (!VerifyVeraCryptInstaller(installerPath))
    {
        DeleteFileW(installerPath.c_str());
        SetStatus(L"Le fichier téléchargé n'a pas passé la vérification d'intégrité.");
        MessageBoxW(g_window,
                    L"Le fichier téléchargé ne correspond pas à l'empreinte officielle attendue. "
                    L"Il a été supprimé et ne sera pas exécuté.",
                    L"Vérification échouée", MB_ICONERROR | MB_OK);
        return false;
    }

    SetStatus(L"Installation de VeraCrypt (confirmez la demande Windows)...");
    UpdateWindow(g_window);
    const std::wstring parameters = L"/i " + Quote(installerPath) + L" /norestart";
    SHELLEXECUTEINFOW execute{};
    execute.cbSize = sizeof(execute);
    execute.fMask = SEE_MASK_NOCLOSEPROCESS;
    execute.lpVerb = L"runas";
    execute.lpFile = L"msiexec.exe";
    execute.lpParameters = parameters.c_str();
    execute.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&execute))
    {
        const DWORD error = GetLastError();
        DeleteFileW(installerPath.c_str());
        SetStatus(L"Impossible de démarrer l'installation.");
        if (error == ERROR_CANCELLED)
            MessageBoxW(g_window, L"L'installation a été annulée dans la demande UAC.",
                        L"Installation annulée", MB_ICONINFORMATION | MB_OK);
        else
            MessageBoxW(g_window,
                        L"Impossible de démarrer l'installation de VeraCrypt. Vérifiez les droits administrateur.",
                        L"Installation impossible", MB_ICONERROR | MB_OK);
        return false;
    }

    const DWORD waitResult = WaitForSingleObject(execute.hProcess, 600000);
    DWORD exitCode = ERROR_INSTALL_FAILURE;
    if (waitResult == WAIT_OBJECT_0)
        GetExitCodeProcess(execute.hProcess, &exitCode);
    CloseHandle(execute.hProcess);
    DeleteFileW(installerPath.c_str());

    if (waitResult != WAIT_OBJECT_0 || (exitCode != ERROR_SUCCESS && exitCode != 3010 && exitCode != 1641))
    {
        SetStatus(L"L'installation de VeraCrypt a échoué.");
        MessageBoxW(g_window,
                    L"L'installation de VeraCrypt n'a pas abouti. Vous pouvez l'installer manuellement depuis veracrypt.io.",
                    L"Installation échouée", MB_ICONERROR | MB_OK);
        return false;
    }

    g_veraCryptPath.clear();
    if (!FindVeraCrypt())
    {
        SetStatus(L"Installation terminée, mais VeraCrypt reste introuvable.");
        MessageBoxW(g_window,
                    L"Le programme d'installation s'est terminé, mais SecureFolder ne trouve pas VeraCrypt "
                    L"dans son emplacement standard. Redémarrez l'application ou installez-le manuellement.",
                    L"VeraCrypt introuvable", MB_ICONERROR | MB_OK);
        return false;
    }

    SetStatus(L"VeraCrypt est installé.");
    MessageBoxW(g_window, L"VeraCrypt est installé. La création du coffre va maintenant s'ouvrir.",
                L"Installation terminée", MB_ICONINFORMATION | MB_OK);
    return true;
}

bool EnsureVeraCrypt()
{
    return FindVeraCrypt() || InstallVeraCrypt();
}

bool RunVeraCrypt(const std::wstring& arguments, DWORD waitMilliseconds = 8000)
{
    if (!EnsureVeraCrypt())
    {
        return false;
    }

    std::wstring command = Quote(g_veraCryptPath) + L" " + arguments;
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(g_veraCryptPath.c_str(), mutableCommand.data(), nullptr, nullptr, FALSE,
                        0, nullptr, nullptr, &startup, &process))
    {
        MessageBoxW(g_window, L"Impossible de démarrer VeraCrypt.", L"Erreur", MB_ICONERROR | MB_OK);
        return false;
    }

    if (waitMilliseconds != 0)
        WaitForSingleObject(process.hProcess, waitMilliseconds);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return true;
}

void SetStatus(const std::wstring& text)
{
    if (g_status)
        SetWindowTextW(g_status, text.c_str());
}

void LoadSettings()
{
    g_settings = Settings{};
    const std::wstring ini = GetSettingsPath();
    if (ini.empty() || GetFileAttributesW(ini.c_str()) == INVALID_FILE_ATTRIBUTES)
        return;

    g_settings.timeoutMinutes = GetPrivateProfileIntW(L"Lock", L"TimeoutMinutes", 15, ini.c_str());
    g_settings.lockOnSleep = GetPrivateProfileIntW(L"Lock", L"LockOnSleep", 1, ini.c_str()) != 0;
    g_settings.lockOnShutdown = GetPrivateProfileIntW(L"Lock", L"LockOnShutdown", 1, ini.c_str()) != 0;
    g_settings.forceUnmount = GetPrivateProfileIntW(L"Lock", L"ForceUnmount", 0, ini.c_str()) != 0;
    if (g_settings.timeoutMinutes > 1440)
        g_settings.timeoutMinutes = 1440;
}

bool SaveSettings()
{
    const std::wstring ini = GetSettingsPath();
    if (ini.empty() || !g_mounted)
    {
        MessageBoxW(g_window, L"Le coffre doit être déverrouillé pour enregistrer ses paramètres.",
                    L"Coffre verrouillé", MB_ICONWARNING | MB_OK);
        return false;
    }

    wchar_t timeoutText[16]{};
    GetWindowTextW(g_timeoutEdit, timeoutText, static_cast<int>(std::size(timeoutText)));
    wchar_t* end = nullptr;
    const unsigned long parsed = wcstoul(timeoutText, &end, 10);
    if (end == timeoutText || *end != L'\0' || parsed > 1440)
    {
        MessageBoxW(g_window, L"Le délai doit être compris entre 0 et 1440 minutes. 0 désactive le délai.",
                    L"Paramètre invalide", MB_ICONWARNING | MB_OK);
        return false;
    }

    const Settings updated{
        static_cast<unsigned>(parsed),
        SendMessageW(g_sleepCheck, BM_GETCHECK, 0, 0) == BST_CHECKED,
        SendMessageW(g_shutdownCheck, BM_GETCHECK, 0, 0) == BST_CHECKED,
        SendMessageW(g_forceCheck, BM_GETCHECK, 0, 0) == BST_CHECKED
    };
    const auto writeNumber = [&ini](const wchar_t* key, unsigned value)
    {
        wchar_t text[16]{};
        _snwprintf_s(text, std::size(text), _TRUNCATE, L"%u", value);
        return WritePrivateProfileStringW(L"Lock", key, text, ini.c_str()) != FALSE;
    };
    const bool written =
        writeNumber(L"TimeoutMinutes", updated.timeoutMinutes) &&
        writeNumber(L"LockOnSleep", updated.lockOnSleep ? 1U : 0U) &&
        writeNumber(L"LockOnShutdown", updated.lockOnShutdown ? 1U : 0U) &&
        writeNumber(L"ForceUnmount", updated.forceUnmount ? 1U : 0U);
    if (!written)
    {
        MessageBoxW(g_window, L"Impossible d'enregistrer les paramètres dans le coffre déverrouillé.",
                    L"Erreur d'écriture", MB_ICONERROR | MB_OK);
        return false;
    }

    SetFileAttributesW(ini.c_str(), FILE_ATTRIBUTE_HIDDEN);
    g_settings = updated;
    g_settingsUnlocked = false;
    EnableWindow(g_timeoutEdit, FALSE);
    EnableWindow(g_sleepCheck, FALSE);
    EnableWindow(g_shutdownCheck, FALSE);
    EnableWindow(g_forceCheck, FALSE);
    EnableWindow(g_saveButton, FALSE);
    SetStatus(L"Paramètres enregistrés.");
    if (g_mounted)
        g_mountedAt = GetTickCount64();
    return true;
}

bool FindFreeDrive(wchar_t& letter)
{
    const DWORD drives = GetLogicalDrives();
    for (wchar_t candidate = L'Z'; candidate >= L'G'; --candidate)
    {
        const DWORD mask = 1U << (candidate - L'A');
        if ((drives & mask) == 0)
        {
            letter = candidate;
            return true;
        }
    }
    return false;
}

bool LaunchMount(const std::wstring& path, bool authenticateForSettings, bool keepOpenAfterAuthentication = false)
{
    if (!EnsureVeraCrypt())
        return false;
    if (g_mountPending || g_mounted)
        return false;

    wchar_t drive = L'\0';
    if (!FindFreeDrive(drive))
    {
        MessageBoxW(g_window, L"Aucune lettre de lecteur libre n'est disponible.",
                    L"Impossible de monter le coffre", MB_ICONERROR | MB_OK);
        return false;
    }

    g_currentPath = path;
    g_driveLetter = drive;
    g_settingsAuthentication = authenticateForSettings;
    g_keepOpenAfterAuthentication = keepOpenAfterAuthentication;
    g_mountPending = true;
    g_mountStarted = GetTickCount64();
    SetStatus(L"En attente de la saisie du mot de passe dans VeraCrypt...");

    std::wstring arguments = L"/q /v " + Quote(path) + L" /l ";
    arguments.push_back(drive);
    arguments += L" /secureDesktop y /c n /h n";
    std::wstring command = Quote(g_veraCryptPath) + L" " + arguments;
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(g_veraCryptPath.c_str(), mutableCommand.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process))
    {
        g_mountPending = false;
        SetStatus(L"Échec du lancement de VeraCrypt.");
        MessageBoxW(g_window, L"Impossible de démarrer VeraCrypt.", L"Erreur", MB_ICONERROR | MB_OK);
        return false;
    }

    g_mountProcess = process.hProcess;
    CloseHandle(process.hThread);
    SetTimer(g_window, kTimerId, 500, nullptr);
    return true;
}

bool WaitForUnmount(wchar_t letter, DWORD timeoutMilliseconds)
{
    const ULONGLONG started = GetTickCount64();
    while (GetTickCount64() - started < timeoutMilliseconds)
    {
        if (!IsDriveMounted(letter))
            return true;
        Sleep(100);
    }
    return !IsDriveMounted(letter);
}

std::wstring GetWindowTitle(HWND window)
{
    const int length = GetWindowTextLengthW(window);
    if (length <= 0)
        return L"(titre indisponible)";

    std::wstring title(static_cast<size_t>(length) + 1, L'\0');
    const int copied = GetWindowTextW(window, title.data(), length + 1);
    if (copied <= 0)
        return L"(titre indisponible)";
    title.resize(static_cast<size_t>(copied));
    return title;
}

bool SaveAndCloseMountedFolderFiles(
    wchar_t letter,
    bool forceCloseAfterSaveFailure = false,
    bool confirmWindows = true)
{
    wininfo::WindowSaveManager windows;
    std::vector<HWND> matchingWindows;
    std::unordered_set<HWND> uniqueWindows;
    const std::filesystem::path root(std::wstring(1, letter) + L":\\");
    std::error_code error;
    std::filesystem::recursive_directory_iterator entry(root, error);
    if (error)
    {
        SetStatus(L"Impossible de parcourir les fichiers du coffre.");
        MessageBoxW(g_window, L"Impossible de parcourir le coffre. Vérifiez qu'il est accessible, puis réessayez.",
                    L"Préparation du verrouillage impossible", MB_ICONERROR | MB_OK);
        return false;
    }

    const std::filesystem::recursive_directory_iterator end;
    while (entry != end)
    {
        const std::filesystem::path path = entry->path();
        const DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            SetStatus(L"Impossible d'identifier un fichier du coffre.");
            MessageBoxW(g_window, L"Un fichier du coffre a changé pendant l'analyse. Réessayez.",
                        L"Préparation du verrouillage impossible", MB_ICONERROR | MB_OK);
            return false;
        }

        if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                entry.disable_recursion_pending();
        }
        else if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
        {
            for (const HWND window : windows.FindWindowsForFile(path))
            {
                if (uniqueWindows.insert(window).second)
                    matchingWindows.push_back(window);
            }
        }

        entry.increment(error);
        if (error)
        {
            SetStatus(L"Impossible de terminer l'analyse des fichiers du coffre.");
            MessageBoxW(g_window, L"Impossible de terminer l'analyse du coffre. Vérifiez qu'il est accessible, puis réessayez.",
                        L"Préparation du verrouillage impossible", MB_ICONERROR | MB_OK);
            return false;
        }
    }

    if (matchingWindows.empty())
        return true;

    if (confirmWindows)
    {
        std::wstring prompt =
            L"SecureFolder a repéré des fenêtres visibles dont le titre correspond au nom d'un fichier "
            L"du coffre :\n\n";
        constexpr size_t kMaxTitlesToShow = 12;
        for (size_t index = 0; index < matchingWindows.size() && index < kMaxTitlesToShow; ++index)
            prompt += L"• " + GetWindowTitle(matchingWindows[index]) + L"\n";
        if (matchingWindows.size() > kMaxTitlesToShow)
            prompt += L"... et " + std::to_wstring(matchingWindows.size() - kMaxTitlesToShow) + L" autre(s)\n";
        prompt +=
            L"\nWindowsInfo va envoyer Ctrl+S puis demander la fermeture de ces fenêtres. "
            L"La correspondance se fait par nom de fichier dans le titre, pas par chemin complet; "
            L"la sauvegarde ne peut pas être vérifiée. Les applications peuvent afficher leur propre "
            L"boîte de dialogue. Si une fenêtre ne se ferme pas, le coffre ne sera pas démonté.\n\n"
            L"Continuer ?";
        if (MessageBoxW(g_window, prompt.c_str(), L"Enregistrer et fermer les fichiers",
                        MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES)
        {
            SetStatus(L"Verrouillage annulé.");
            return false;
        }
    }

    SetStatus(L"Envoi de Ctrl+S aux fenêtres repérées...");
    for (const HWND window : matchingWindows)
    {
        if (IsWindow(window))
            windows.SaveWindow(window);
    }

    if (forceCloseAfterSaveFailure)
    {
        SetStatus(L"Attente de 10 secondes pour laisser les applications enregistrer...");
        UpdateWindow(g_status);
        Sleep(10000);
    }

    SetStatus(L"Fermeture des fenêtres repérées...");
    for (const HWND window : matchingWindows)
    {
        if (IsWindow(window) && !windows.CloseWindow(window, true))
        {
            SetStatus(L"Impossible de demander la fermeture d'une fenêtre du coffre.");
            MessageBoxW(g_window,
                        L"Impossible de demander la fermeture de toutes les fenêtres repérées. "
                        L"Le coffre reste déverrouillé.",
                        L"Fermeture impossible", MB_ICONWARNING | MB_OK);
            return false;
        }
    }

    const ULONGLONG closeStarted = GetTickCount64();
    for (;;)
    {
        bool allClosed = true;
        for (const HWND window : matchingWindows)
            allClosed = allClosed && !IsWindow(window);
        if (allClosed)
            return true;
        if (GetTickCount64() - closeStarted >= (forceCloseAfterSaveFailure ? 500 : 15000))
            break;
        Sleep(100);
    }

    if (forceCloseAfterSaveFailure)
    {
        std::unordered_set<DWORD> processIds;
        for (const HWND window : matchingWindows)
        {
            if (!IsWindow(window))
                continue;
            DWORD processId = 0;
            GetWindowThreadProcessId(window, &processId);
            if (processId != 0 && processId != GetCurrentProcessId())
                processIds.insert(processId);
        }

        for (const DWORD processId : processIds)
        {
            HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, processId);
            if (!process)
                continue;
            TerminateProcess(process, ERROR_CANCELLED);
            WaitForSingleObject(process, 3000);
            CloseHandle(process);
        }

        bool allClosed = true;
        for (const HWND window : matchingWindows)
            allClosed = allClosed && !IsWindow(window);
        if (allClosed)
            return true;
    }

    SetStatus(L"Certaines fenêtres du coffre sont toujours ouvertes.");
    MessageBoxW(g_window,
                L"Certaines fenêtres ne se sont pas fermées. Répondez aux éventuelles boîtes de dialogue "
                L"des applications, puis réessayez. Le coffre reste déverrouillé.",
                L"Fermeture incomplète", MB_ICONWARNING | MB_OK);
    return false;
}

bool Dismount(bool permitForce)
{
    if (!g_mounted && !g_mountPending)
        return true;

    if (g_mountPending)
    {
        if (!IsDriveMounted(g_driveLetter))
        {
            if (g_mountProcess)
            {
                TerminateProcess(g_mountProcess, 1);
                CloseHandle(g_mountProcess);
                g_mountProcess = nullptr;
            }
            g_mountPending = false;
            SetStatus(L"Opération de montage annulée.");
            return true;
        }
        g_mountPending = false;
        g_mounted = true;
    }

    SetStatus(L"Verrouillage du coffre...");
    std::wstring arguments = L"/q /u ";
    arguments.push_back(g_driveLetter);
    arguments += L" /w";
    if (!RunVeraCrypt(arguments))
        return false;

    if (!WaitForUnmount(g_driveLetter, 5000) && permitForce)
    {
        const int answer = MessageBoxW(
            g_window,
            L"Des fichiers ou des applications utilisent encore le coffre. Le démontage forcé peut "
            L"perdre des modifications non enregistrées ou interrompre des écritures.\n\n"
            L"Enregistrer et fermer les documents est préférable. Forcer le démontage quand même ?",
            L"Risque de perte de données", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
        if (answer != IDYES)
        {
            SetStatus(L"Le coffre reste déverrouillé ; le démontage forcé a été annulé.");
            return false;
        }
        std::wstring forceArguments = L"/q /f /u ";
        forceArguments.push_back(g_driveLetter);
        forceArguments += L" /w";
        if (!RunVeraCrypt(forceArguments))
            return false;
    }

    if (!WaitForUnmount(g_driveLetter, 10000))
    {
        SetStatus(L"Le coffre est toujours monté; un programme bloque le démontage.");
        return false;
    }

    g_mounted = false;
    g_driveLetter = L'\0';
    g_mountedAt = 0;
    SetStatus(L"Coffre verrouillé.");
    return true;
}

void SetSettingsControls(bool enabled)
{
    EnableWindow(g_timeoutEdit, enabled);
    EnableWindow(g_sleepCheck, enabled);
    EnableWindow(g_shutdownCheck, enabled);
    EnableWindow(g_forceCheck, enabled);
    EnableWindow(g_saveButton, enabled);
    if (!enabled)
        g_settingsUnlocked = false;
}

void DisplaySettings()
{
    wchar_t timeout[16]{};
    _snwprintf_s(timeout, std::size(timeout), _TRUNCATE, L"%u", g_settings.timeoutMinutes);
    SetWindowTextW(g_timeoutEdit, timeout);
    SendMessageW(g_sleepCheck, BM_SETCHECK, g_settings.lockOnSleep ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(g_shutdownCheck, BM_SETCHECK, g_settings.lockOnShutdown ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(g_forceCheck, BM_SETCHECK, g_settings.forceUnmount ? BST_CHECKED : BST_UNCHECKED, 0);
    SetSettingsControls(true);
    g_settingsUnlocked = true;
    SetStatus(L"Mot de passe vérifié. Modifiez les paramètres puis enregistrez.");
}

bool AuthenticateSettings()
{
    if (g_currentPath.empty())
    {
        MessageBoxW(g_window, L"Ouvrez d'abord un fichier .sf.", L"Paramètres", MB_ICONINFORMATION | MB_OK);
        return false;
    }
    if (g_mounted)
    {
        const int answer = MessageBoxW(
            g_window,
            L"Pour vérifier à nouveau le mot de passe, le coffre doit être démonté puis remonté. "
            L"SecureFolder va repérer les fenêtres liées aux fichiers du coffre et tenter de les enregistrer "
            L"et de les fermer avant de continuer.",
            L"Vérifier le mot de passe", MB_ICONWARNING | MB_OKCANCEL);
        if (answer != IDOK)
            return false;
        if (!SaveAndCloseMountedFolderFiles(g_driveLetter))
            return false;
        if (!Dismount(false))
        {
            MessageBoxW(g_window,
                        L"Le coffre n'a pas été démonté. Enregistrez et fermez les fichiers ouverts, puis réessayez.",
                        L"Coffre toujours ouvert", MB_ICONWARNING | MB_OK);
            return false;
        }
    }

    SetSettingsControls(false);
    return LaunchMount(g_currentPath, true);
}

bool ReauthenticateToKeepOpen()
{
    if (!g_mounted || g_currentPath.empty() || g_reauthenticationInProgress)
        return false;

    struct ReauthenticationGuard
    {
        explicit ReauthenticationGuard(bool& active) : active_(active)
        {
            active_ = true;
        }
        ~ReauthenticationGuard()
        {
            active_ = false;
        }
        bool& active_;
    } guard(g_reauthenticationInProgress);

    const int answer = MessageBoxW(
        g_window,
        L"Le délai de déverrouillage est écoulé. SecureFolder va tenter d'enregistrer et de fermer les fenêtres "
        L"des fichiers du coffre. Après 10 secondes, les applications toujours ouvertes pourront être terminées.\n\n"
        L"Choisissez OK pour verrouiller temporairement le coffre et saisir à nouveau le mot de passe. "
        L"Un mot de passe correct le remontera. Annuler verrouille le coffre sans le remonter.",
        L"Réauthentification requise", MB_ICONWARNING | MB_OKCANCEL);
    const std::wstring path = g_currentPath;
    if (!SaveAndCloseMountedFolderFiles(g_driveLetter, true, false))
    {
        g_mountedAt = GetTickCount64();
        return false;
    }
    if (!Dismount(false))
    {
        if (!g_settings.forceUnmount || !Dismount(true))
        {
            MessageBoxW(g_window,
                        L"Le coffre reste déverrouillé. Enregistrez et fermez les fichiers ouverts, puis verrouillez-le.",
                        L"Verrouillage annulé", MB_ICONWARNING | MB_OK);
            g_mountedAt = GetTickCount64();
            return false;
        }
    }
    return answer == IDOK ? LaunchMount(path, false, true) : false;
}

bool ChooseVaultPath(std::wstring& path)
{
    std::vector<wchar_t> selectedPath(32768);
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = g_window;
    dialog.lpstrFilter = L"Coffres SecureFolder (*.sf)\0*.sf\0Tous les fichiers (*.*)\0*.*\0\0";
    dialog.lpstrFile = selectedPath.data();
    dialog.nMaxFile = static_cast<DWORD>(selectedPath.size());
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    dialog.lpstrDefExt = L"sf";
    if (!GetOpenFileNameW(&dialog))
        return false;
    path = selectedPath.data();
    return true;
}

void ChangeVaultSelection()
{
    std::wstring path;
    if (!ChooseVaultPath(path))
        return;
    if (g_mounted && !Dismount(false))
    {
        MessageBoxW(g_window, L"Le coffre actuel est toujours ouvert. La sélection n'a pas été changée.",
                    L"Impossible de changer de coffre", MB_ICONWARNING | MB_OK);
        return;
    }
    g_currentPath = path;
    SetWindowTextW(g_pathLabel, g_currentPath.c_str());
    SetSettingsControls(false);
    SetStatus(L"Nouveau coffre sélectionné.");
    UpdateControls();
}

void OpenFile()
{
    std::wstring path = g_currentPath;
    if (path.empty() && !ChooseVaultPath(path))
        return;

    if (g_mounted && !Dismount(false))
    {
        MessageBoxW(g_window, L"Verrouillez d'abord le coffre actuellement ouvert.",
                    L"Impossible d'ouvrir un autre coffre", MB_ICONWARNING | MB_OK);
        return;
    }
    g_currentPath = path;
    SetWindowTextW(g_pathLabel, g_currentPath.c_str());
    SetSettingsControls(false);
    LaunchMount(g_currentPath, false);
}

void CreateVault(const std::wstring& initialDirectory = {})
{
    if (!EnsureVeraCrypt())
        return;
    if (!initialDirectory.empty())
    {
        const DWORD attributes = GetFileAttributesW(initialDirectory.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
        {
            MessageBoxW(g_window, L"Le dossier choisi n'existe plus ou n'est pas accessible.",
                        L"Dossier invalide", MB_ICONERROR | MB_OK);
            return;
        }
    }

    const std::wstring formatPath = FindVeraCryptFormat();
    if (formatPath.empty())
    {
        MessageBoxW(g_window,
                    L"VeraCrypt Format.exe est introuvable. Réparez ou réinstallez VeraCrypt depuis veracrypt.io.",
                    L"Assistant de création indisponible", MB_ICONERROR | MB_OK);
        return;
    }
    std::wstring prompt =
        L"L'assistant officiel VeraCrypt va s'ouvrir pour créer le coffre chiffré.\n\n"
        L"1. Choisissez « Create an encrypted file container », puis « Standard VeraCrypt volume ».\n"
        L"2. Choisissez le chemin et donnez au fichier le nom souhaité terminé par .sf";
    if (!initialDirectory.empty())
        prompt += L" (le dossier sélectionné dans l'Explorateur est proposé comme emplacement de départ)";
    prompt +=
        L".\n"
        L"3. Saisissez et confirmez le mot de passe dans VeraCrypt ; SecureFolder ne le collecte pas.\n"
        L"4. Gardez les algorithmes et les autres options par défaut. Choisissez une taille d'au moins 10 Mo.\n"
        L"5. Sur l'écran de génération aléatoire, bougez la souris jusqu'à ce que l'indicateur soit rempli, "
        L"puis terminez le formatage.\n\n"
        L"VeraCrypt exige ces étapes interactives pour utiliser son générateur et protéger le mot de passe. "
        L"L'extension .sf doit être saisie dans le chemin de l'assistant VeraCrypt.";
    const int answer = MessageBoxW(
        g_window, prompt.c_str(),
        L"Créer un coffre .sf", MB_ICONINFORMATION | MB_OKCANCEL);
    if (answer != IDOK)
        return;

    SHELLEXECUTEINFOW execute{};
    execute.cbSize = sizeof(execute);
    execute.fMask = SEE_MASK_NOCLOSEPROCESS;
    execute.lpFile = formatPath.c_str();
    execute.lpDirectory = initialDirectory.empty() ? nullptr : initialDirectory.c_str();
    execute.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&execute))
    {
        MessageBoxW(g_window, L"Impossible de démarrer l'assistant de création VeraCrypt.",
                    L"Erreur", MB_ICONERROR | MB_OK);
        return;
    }
    if (execute.hProcess)
        CloseHandle(execute.hProcess);
    SetStatus(L"Assistant de création VeraCrypt lancé.");
}

void RegisterAssociation()
{
    const std::wstring executable = GetRunningExecutable();
    if (executable.empty())
    {
        MessageBoxW(g_window, L"Impossible de déterminer le chemin de SecureFolder.exe.",
                    L"Erreur", MB_ICONERROR | MB_OK);
        return;
    }

    HKEY key = nullptr;
    DWORD disposition = 0;
    struct RegistryValue
    {
        const wchar_t* path;
        std::wstring value;
    };
    const std::vector<RegistryValue> values = {
        {L"Software\\Classes\\.sf", L"SecureFolder.Container"},
        {L"Software\\Classes\\SecureFolder.Container", L""},
        {L"Software\\Classes\\SecureFolder.Container\\DefaultIcon", Quote(executable) + L",0"},
        {L"Software\\Classes\\SecureFolder.Container\\shell\\open\\command", Quote(executable) + L" \"%1\""},
        {L"Software\\Classes\\Directory\\shell\\SecureFolder.CreateVault", L"Créer un coffre SecureFolder ici (.sf)"},
        {L"Software\\Classes\\Directory\\shell\\SecureFolder.CreateVault\\command",
         Quote(executable) + L" --create-vault \"%1\""},
        {L"Software\\Classes\\Directory\\Background\\shell\\SecureFolder.CreateVault",
         L"Créer un coffre SecureFolder ici (.sf)"},
        {L"Software\\Classes\\Directory\\Background\\shell\\SecureFolder.CreateVault\\command",
         Quote(executable) + L" --create-vault \"%V\""}
    };
    bool success = true;
    for (const RegistryValue& registryValue : values)
    {
        if (RegCreateKeyExW(HKEY_CURRENT_USER, registryValue.path, 0, nullptr, 0, KEY_SET_VALUE,
                            nullptr, &key, &disposition) != ERROR_SUCCESS)
        {
            success = false;
            break;
        }
        if (!registryValue.value.empty() &&
            RegSetValueExW(key, nullptr, 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(registryValue.value.c_str()),
                           static_cast<DWORD>((registryValue.value.size() + 1) * sizeof(wchar_t))) != ERROR_SUCCESS)
            success = false;
        RegCloseKey(key);
        key = nullptr;
        if (!success)
            break;
    }

    if (!success)
    {
        if (key)
            RegCloseKey(key);
        MessageBoxW(g_window, L"Impossible d'enregistrer l'association .sf ou le menu contextuel pour cet utilisateur.",
                    L"Erreur", MB_ICONERROR | MB_OK);
        return;
    }

    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
    MessageBoxW(g_window,
                L"L'association .sf et les commandes de création par clic droit sont enregistrées pour cet utilisateur.\n\n"
                L"Windows peut demander de choisir SecureFolder dans Paramètres > Applications > Applications par défaut "
                L"avant que le double-clic ouvre ces fichiers. Dans l'Explorateur, cliquez avec le bouton droit sur un dossier "
                L"ou dans son arrière-plan, puis choisissez « Créer un coffre SecureFolder ici (.sf) ».",
                L"Association et menu contextuel enregistrés", MB_ICONINFORMATION | MB_OK);
    ShellExecuteW(g_window, L"open", L"ms-settings:defaultapps", nullptr, nullptr, SW_SHOWNORMAL);
}

void HandleMountTimer()
{
    if (g_mountPending)
    {
        if (IsDriveMounted(g_driveLetter))
        {
            g_mountPending = false;
            if (g_mountProcess)
            {
                CloseHandle(g_mountProcess);
                g_mountProcess = nullptr;
            }

            if (g_settingsAuthentication)
            {
                g_mounted = true;
                g_mountedAt = GetTickCount64();
                LoadSettings();
                DisplaySettings();
                ShellExecuteW(g_window, L"open",
                              (std::wstring(1, g_driveLetter) + L":\\").c_str(),
                              nullptr, nullptr, SW_SHOWNORMAL);
                return;
            }

            g_mounted = true;
            g_mountedAt = GetTickCount64();
            LoadSettings();
            SetWindowTextW(g_pathLabel, g_currentPath.c_str());
            SetStatus(g_keepOpenAfterAuthentication
                          ? std::wstring(L"Mot de passe accepté ; coffre remonté sur le lecteur ") + g_driveLetter + L":"
                          : std::wstring(L"Coffre déverrouillé sur le lecteur ") + g_driveLetter + L":");
            g_keepOpenAfterAuthentication = false;
            ShellExecuteW(g_window, L"open", (std::wstring(1, g_driveLetter) + L":\\").c_str(),
                          nullptr, nullptr, SW_SHOWNORMAL);
            return;
        }

        if (g_mountProcess)
        {
            DWORD exitCode = STILL_ACTIVE;
            if (GetExitCodeProcess(g_mountProcess, &exitCode) && exitCode != STILL_ACTIVE)
            {
                CloseHandle(g_mountProcess);
                g_mountProcess = nullptr;
                g_mountPending = false;
                SetStatus(L"VeraCrypt a annulé le montage ou le mot de passe est incorrect.");
                MessageBoxW(g_window,
                            L"Le coffre n'a pas été monté. Vérifiez le mot de passe et réessayez.",
                            L"Montage annulé ou refusé", MB_ICONWARNING | MB_OK);
                return;
            }
        }

        if (GetTickCount64() - g_mountStarted > 180000)
        {
            g_mountPending = false;
            if (g_mountProcess)
            {
                DWORD exitCode = STILL_ACTIVE;
                if (GetExitCodeProcess(g_mountProcess, &exitCode) && exitCode == STILL_ACTIVE)
                    TerminateProcess(g_mountProcess, 1);
                CloseHandle(g_mountProcess);
                g_mountProcess = nullptr;
            }
            SetStatus(L"Délai de montage dépassé.");
            MessageBoxW(g_window, L"Le montage n'a pas abouti dans le délai imparti.",
                        L"Échec du montage", MB_ICONWARNING | MB_OK);
            return;
        }
    }
    else if (g_mounted && g_settings.timeoutMinutes > 0 &&
             !g_reauthenticationInProgress &&
             GetTickCount64() - g_mountedAt >=
                 static_cast<ULONGLONG>(g_settings.timeoutMinutes) * 60ULL * 1000ULL)
    {
        ReauthenticateToKeepOpen();
    }
}

void UpdateControls()
{
    const bool hasPath = !g_currentPath.empty();
    EnableWindow(g_settingsButton, hasPath && !g_mountPending);
    EnableWindow(g_lockButton, g_mounted || g_mountPending);
    EnableWindow(g_openButton, !g_mountPending && !g_mounted);
    EnableWindow(g_selectButton, !g_mountPending);
    EnableWindow(g_createButton, !g_mountPending && !g_mounted);
    EnableWindow(g_associateButton, TRUE);
}

void LayoutControls(HWND window)
{
    RECT client{};
    GetClientRect(window, &client);
    const int width = client.right - client.left;
    const int height = client.bottom - client.top;
    constexpr int margin = 16;
    constexpr int gap = 18;
    const int columnWidth = (width - 2 * margin - gap) / 2;
    const int fullWidth = width - 2 * margin;
    const int rightColumn = margin + columnWidth + gap;
    const int saveY = (height - 76 > 444) ? height - 76 : 444;
    const int noteY = (height - 36 > 484) ? height - 36 : 484;

    MoveWindow(g_pathCaption, margin, 14, fullWidth, 20, TRUE);
    MoveWindow(g_pathLabel, margin, 36, fullWidth - 138, 34, TRUE);
    MoveWindow(g_selectButton, width - margin - 130, 36, 130, 28, TRUE);
    MoveWindow(g_status, margin, 76, fullWidth, 28, TRUE);
    MoveWindow(g_openButton, margin, 112, columnWidth, 32, TRUE);
    MoveWindow(g_createButton, rightColumn, 112, columnWidth, 32, TRUE);
    MoveWindow(g_settingsButton, margin, 154, fullWidth, 32, TRUE);
    MoveWindow(g_lockButton, margin, 196, columnWidth, 32, TRUE);
    MoveWindow(g_associateButton, rightColumn, 196, columnWidth, 32, TRUE);
    MoveWindow(g_settingsCaption, margin, 246, fullWidth, 24, TRUE);
    MoveWindow(g_timeoutCaption, margin, 276, fullWidth, 24, TRUE);
    MoveWindow(g_timeoutEdit, margin, 304, 100, 26, TRUE);
    MoveWindow(g_sleepCheck, margin, 338, fullWidth, 24, TRUE);
    MoveWindow(g_shutdownCheck, margin, 366, fullWidth, 24, TRUE);
    MoveWindow(g_forceCheck, margin, 394, fullWidth, 40, TRUE);
    MoveWindow(g_saveButton, rightColumn, saveY, columnWidth, 32, TRUE);
    MoveWindow(g_settingsNote, margin, noteY, fullWidth, 20, TRUE);
}

LRESULT CALLBACK WindowProcedure(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
        g_window = window;
        g_pathCaption = CreateWindowW(L"STATIC", L"Coffre sélectionné :", WS_CHILD | WS_VISIBLE,
                                      16, 14, 440, 20, window, nullptr, nullptr, nullptr);
        g_pathLabel = CreateWindowW(L"STATIC", L"(aucun)", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS,
                                    16, 36, 448, 34, window, nullptr, nullptr, nullptr);
        g_selectButton = CreateWindowW(L"BUTTON", L"Changer de coffre...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                       16, 36, 130, 28, window, reinterpret_cast<HMENU>(kSelectButton), nullptr, nullptr);
        g_status = CreateWindowW(L"STATIC", L"Verrouillé.", WS_CHILD | WS_VISIBLE,
                                 16, 76, 448, 28, window, nullptr, nullptr, nullptr);
        g_openButton = CreateWindowW(L"BUTTON", L"Ouvrir un coffre .sf", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                     16, 112, 210, 32, window, reinterpret_cast<HMENU>(kOpenButton), nullptr, nullptr);
        g_createButton = CreateWindowW(L"BUTTON", L"Créer un coffre", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                       244, 112, 210, 32, window, reinterpret_cast<HMENU>(kCreateButton), nullptr, nullptr);
        g_settingsButton = CreateWindowW(L"BUTTON", L"Paramètres (mot de passe requis)", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                         16, 154, 438, 32, window, reinterpret_cast<HMENU>(kSettingsButton), nullptr, nullptr);
        g_lockButton = CreateWindowW(L"BUTTON", L"Verrouiller maintenant", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                     16, 196, 210, 32, window, reinterpret_cast<HMENU>(kLockButton), nullptr, nullptr);
        g_associateButton = CreateWindowW(L"BUTTON", L"Associer .sf + clic droit", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                          244, 196, 210, 32, window, reinterpret_cast<HMENU>(kAssociateButton), nullptr, nullptr);
        g_settingsCaption = CreateWindowW(L"STATIC", L"Paramètres du coffre (mot de passe requis)",
                                          WS_CHILD | WS_VISIBLE | SS_LEFT, 16, 246, 440, 24, window, nullptr, nullptr, nullptr);
        g_timeoutCaption = CreateWindowW(L"STATIC", L"Verrouiller après (minutes) ; 0 désactive le délai",
                                        WS_CHILD | WS_VISIBLE | SS_LEFT, 16, 276, 440, 24, window, nullptr, nullptr, nullptr);
        g_timeoutEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"15",
                                        WS_CHILD | WS_VISIBLE | ES_NUMBER | ES_AUTOHSCROLL,
                                        16, 304, 100, 26, window, reinterpret_cast<HMENU>(kTimeoutEdit), nullptr, nullptr);
        g_sleepCheck = CreateWindowW(L"BUTTON", L"Verrouiller avant la mise en veille",
                                     WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 16, 338, 320, 24,
                                     window, reinterpret_cast<HMENU>(kSleepCheck), nullptr, nullptr);
        g_shutdownCheck = CreateWindowW(L"BUTTON", L"Verrouiller avant l'arrêt de Windows",
                                        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,                                         16, 366, 340, 24,
                                        window, reinterpret_cast<HMENU>(kShutdownCheck), nullptr, nullptr);
        g_forceCheck = CreateWindowW(L"BUTTON", L"Forcer le démontage si des fichiers sont ouverts (risque de perte de données)",
                                     WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX | BS_MULTILINE, 16, 394, 448, 40,
                                     window, reinterpret_cast<HMENU>(kForceCheck), nullptr, nullptr);
        g_saveButton = CreateWindowW(L"BUTTON", L"Enregistrer les paramètres",
                                     WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 244, 444, 210, 32,
                                     window, reinterpret_cast<HMENU>(kSaveButton), nullptr, nullptr);
        g_settingsNote = CreateWindowW(L"STATIC", L"Les paramètres sont enregistrés à l'intérieur du volume chiffré .sf.",
                                       WS_CHILD | WS_VISIBLE, 16, 484, 448, 20, window, nullptr, nullptr, nullptr);
        LayoutControls(window);
        SetSettingsControls(false);
        UpdateControls();
        return 0;

    case WM_SIZE:
        LayoutControls(window);
        return 0;

    case WM_GETMINMAXINFO:
    {
        auto* limits = reinterpret_cast<MINMAXINFO*>(lParam);
        RECT minimum{0, 0, 460, 520};
        const DWORD style = static_cast<DWORD>(GetWindowLongPtrW(window, GWL_STYLE));
        const DWORD extendedStyle = static_cast<DWORD>(GetWindowLongPtrW(window, GWL_EXSTYLE));
        AdjustWindowRectEx(&minimum, style, FALSE, extendedStyle);
        limits->ptMinTrackSize.x = minimum.right - minimum.left;
        limits->ptMinTrackSize.y = minimum.bottom - minimum.top;
        return 0;
    }

    case kOpenSelectedMessage:
        if (!g_currentPath.empty())
        {
            SetWindowTextW(g_pathLabel, g_currentPath.c_str());
            LaunchMount(g_currentPath, false);
        }
        return 0;

    case kCreateVaultMessage:
        CreateVault(g_createVaultDirectory);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case kOpenButton:
            OpenFile();
            break;
        case kSelectButton:
            ChangeVaultSelection();
            break;
        case kCreateButton:
            CreateVault();
            break;
        case kSettingsButton:
            AuthenticateSettings();
            break;
        case kLockButton:
            if (Dismount(g_settings.forceUnmount))
                SetSettingsControls(false);
            else
                MessageBoxW(window, L"Fermez les fichiers ouverts puis réessayez.",
                            L"Échec du verrouillage", MB_ICONWARNING | MB_OK);
            break;
        case kAssociateButton:
            RegisterAssociation();
            break;
        case kSaveButton:
            if (g_settingsUnlocked)
                SaveSettings();
            break;
        }
        UpdateControls();
        return 0;

    case WM_TIMER:
        if (wParam == kTimerId)
        {
            HandleMountTimer();
            UpdateControls();
        }
        return 0;

    case WM_POWERBROADCAST:
        if ((wParam == PBT_APMQUERYSUSPEND || wParam == PBT_APMSUSPEND) &&
            g_settings.lockOnSleep && (g_mounted || g_mountPending))
        {
            if (!Dismount(g_settings.forceUnmount))
            {
                SetStatus(L"Impossible de verrouiller le coffre avant la veille.");
                MessageBoxW(window,
                            L"Un programme bloque le démontage du coffre. Fermez les fichiers ouverts "
                            L"ou activez le démontage forcé dans les paramètres.",
                            L"Veille annulée", MB_ICONWARNING | MB_OK);
                return BROADCAST_QUERY_DENY;
            }
            UpdateControls();
        }
        return TRUE;

    case WM_QUERYENDSESSION:
        if (g_settings.lockOnShutdown && (g_mounted || g_mountPending))
        {
            if (!Dismount(g_settings.forceUnmount))
            {
                MessageBoxW(window,
                            L"Le coffre n'a pas pu être verrouillé. L'arrêt de Windows est annulé pour protéger vos données.",
                            L"Arrêt annulé", MB_ICONWARNING | MB_OK);
                return FALSE;
            }
        }
        return TRUE;

    case WM_CLOSE:
        if (g_mounted || g_mountPending)
        {
            if (!Dismount(g_settings.forceUnmount))
            {
                MessageBoxW(window, L"Fermez les fichiers ouverts avant de quitter SecureFolder.",
                            L"Impossible de quitter", MB_ICONWARNING | MB_OK);
                return 0;
            }
        }
        DestroyWindow(window);
        return 0;

    case WM_DESTROY:
        KillTimer(window, kTimerId);
        if (g_mountProcess)
        {
            CloseHandle(g_mountProcess);
            g_mountProcess = nullptr;
        }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, wParam, lParam);
}
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE, LPSTR, int showCommand)
{
    SetProcessDPIAware();

    int argumentCount = 0;
    wchar_t** arguments = CommandLineToArgvW(GetCommandLineW(), &argumentCount);
    bool createVaultFromExplorer = false;
    if (arguments && argumentCount > 1)
    {
        if (wcscmp(arguments[1], L"--create-vault") == 0 && argumentCount > 2)
        {
            g_createVaultDirectory = arguments[2];
            createVaultFromExplorer = true;
        }
        else
        {
            g_currentPath = arguments[1];
        }
    }
    if (arguments)
        LocalFree(arguments);

    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = WindowProcedure;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    windowClass.lpszClassName = kWindowClass;
    if (!RegisterClassW(&windowClass))
        return 1;

    HWND window = CreateWindowExW(0, kWindowClass, L"SecureFolder",
                                  WS_OVERLAPPEDWINDOW,
                                  CW_USEDEFAULT, CW_USEDEFAULT, 490, 560,
                                  nullptr, nullptr, instance, nullptr);
    if (!window)
        return 1;

    ShowWindow(window, showCommand);
    UpdateWindow(window);
    if (createVaultFromExplorer)
        PostMessageW(window, kCreateVaultMessage, 0, 0);
    else if (!g_currentPath.empty())
        PostMessageW(window, kOpenSelectedMessage, 0, 0);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return static_cast<int>(message.wParam);
}
