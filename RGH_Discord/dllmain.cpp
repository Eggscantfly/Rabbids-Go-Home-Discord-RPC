#include "pch.h"
#include "discord_rpc.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <cstdio>

#define DISCORD_APP_ID "1450006769639358526"
#define VID_GPO_ENGINE_ADDR 0x00A70BA0
#define STUFF_PTR_ADDR 0x00671A34

#define LEVEL_MENU              0x7B0003C8
#define LEVEL_CREDITS           0xDB00D632
#define LEVEL_CUTSCENE          0xB4100DC7
#define LEVEL_RULES             0x561034DD
#define LEVEL_BONANZA           0x4900AC50
#define LEVEL_WACK              0x09200EC6
#define LEVEL_MOONING           0x08102F00
#define LEVEL_SHOP              0x060015C3
#define LEVEL_BACKWATER         0x5100716C
#define LEVEL_PLANE             0x4900AF11
#define LEVEL_BLUES             0xCE101765
#define LEVEL_NICK              0x120026AD
#define LEVEL_SUPER             0x12003FCD
#define LEVEL_ENGINE            0x4900AF1D
#define LEVEL_TILL              0x06002156
#define LEVEL_INFECTIOUS        0x0A002E9D
#define LEVEL_COUNTRY           0x490022CA
#define LEVEL_STAKES            0x09002629
#define LEVEL_TOTALLY           0x51009462

static HANDLE g_hProcess = NULL;
static uintptr_t g_BaseAddress = 0;
static bool g_DiscordReady = false;
static uint32_t g_LastLevelID = 0;
static int32_t g_LastStuffCount = -1;
static char g_StuffString[64] = {0};
static time_t g_StartTime = 0;

static int32_t ReadStuffCount();

static void HandleDiscordReady(const DiscordUser* user) { g_DiscordReady = true; }
static void HandleDiscordDisconnected(int errcode, const char* message) { g_DiscordReady = false; }
static void HandleDiscordError(int errcode, const char* message) {}

static void UpdatePresence_Menu() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.state = "Selecting World";
    discordPresence.details = "Menu";
    discordPresence.largeImageKey = "menu";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Credits() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Watching Credits";
    discordPresence.largeImageKey = "clapper";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Cutscene() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Watching Cutscene";
    discordPresence.largeImageKey = "clapper";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Rules() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Playing Rules Are For Tools";
    sprintf_s(g_StuffString, sizeof(g_StuffString), "Stuff Collected: %d", ReadStuffCount());
    discordPresence.state = g_StuffString;
    discordPresence.largeImageKey = "rules";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Bonanza() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Playing Bubble Bed Bonanza";
    sprintf_s(g_StuffString, sizeof(g_StuffString), "Stuff Collected: %d", ReadStuffCount());
    discordPresence.state = g_StuffString;
    discordPresence.largeImageKey = "bubble";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Wack() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Playing Wack-a-Wabbid";
    sprintf_s(g_StuffString, sizeof(g_StuffString), "Stuff Collected: %d", ReadStuffCount());
    discordPresence.state = g_StuffString;
    discordPresence.largeImageKey = "wack";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Mooning() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Playing Moo-ning Miami";
    sprintf_s(g_StuffString, sizeof(g_StuffString), "Stuff Collected: %d", ReadStuffCount());
    discordPresence.state = g_StuffString;
    discordPresence.largeImageKey = "cow";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Shop() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Playing Shop Till You Drop";
    sprintf_s(g_StuffString, sizeof(g_StuffString), "Stuff Collected: %d", ReadStuffCount());
    discordPresence.state = g_StuffString;
    discordPresence.largeImageKey = "shop";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Backwater() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Playing Backwater Rabbids";
    sprintf_s(g_StuffString, sizeof(g_StuffString), "Stuff Collected: %d", ReadStuffCount());
    discordPresence.state = g_StuffString;
    discordPresence.largeImageKey = "backwater";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Plane() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Playing Just Plane Dumb";
    sprintf_s(g_StuffString, sizeof(g_StuffString), "Stuff Collected: %d", ReadStuffCount());
    discordPresence.state = g_StuffString;
    discordPresence.largeImageKey = "plane";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Blues() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Playing Bubble Bed Blues";
    sprintf_s(g_StuffString, sizeof(g_StuffString), "Stuff Collected: %d", ReadStuffCount());
    discordPresence.state = g_StuffString;
    discordPresence.largeImageKey = "bubble";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Nick() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Playing In The Nick Of Time";
    sprintf_s(g_StuffString, sizeof(g_StuffString), "Stuff Collected: %d", ReadStuffCount());
    discordPresence.state = g_StuffString;
    discordPresence.largeImageKey = "time";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Super() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Playing Super Racket";
    sprintf_s(g_StuffString, sizeof(g_StuffString), "Stuff Collected: %d", ReadStuffCount());
    discordPresence.state = g_StuffString;
    discordPresence.largeImageKey = "shop";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Engine() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Playing Rabbids Fire Reaction";
    sprintf_s(g_StuffString, sizeof(g_StuffString), "Stuff Collected: %d", ReadStuffCount());
    discordPresence.state = g_StuffString;
    discordPresence.largeImageKey = "engine";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Till() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Playing Till Rabbids Do Us Cart";
    sprintf_s(g_StuffString, sizeof(g_StuffString), "Stuff Collected: %d", ReadStuffCount());
    discordPresence.state = g_StuffString;
    discordPresence.largeImageKey = "bubble";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Infectious() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Playing Infectious Blues";
    sprintf_s(g_StuffString, sizeof(g_StuffString), "Stuff Collected: %d", ReadStuffCount());
    discordPresence.state = g_StuffString;
    discordPresence.largeImageKey = "bubble";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Country() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Playing Country Free For All";
    sprintf_s(g_StuffString, sizeof(g_StuffString), "Stuff Collected: %d", ReadStuffCount());
    discordPresence.state = g_StuffString;
    discordPresence.largeImageKey = "country";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Stakes() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Playing High Stakes Steak";
    sprintf_s(g_StuffString, sizeof(g_StuffString), "Stuff Collected: %d", ReadStuffCount());
    discordPresence.state = g_StuffString;
    discordPresence.largeImageKey = "cow";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Totally() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Playing Totally Tubing";
    sprintf_s(g_StuffString, sizeof(g_StuffString), "Stuff Collected: %d", ReadStuffCount());
    discordPresence.state = g_StuffString;
    discordPresence.largeImageKey = "totally";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static void UpdatePresence_Unknown() {
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.details = "Playing Unknown Area";
    discordPresence.largeImageKey = "menu";
    discordPresence.startTimestamp = g_StartTime;
    Discord_UpdatePresence(&discordPresence);
}

static bool FindProcess(const wchar_t* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    DWORD pid = 0;
    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }
    CloseHandle(snapshot);

    if (pid == 0) return false;

    g_hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!g_hProcess) return false;

    HANDLE modSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (modSnapshot == INVALID_HANDLE_VALUE) {
        CloseHandle(g_hProcess);
        g_hProcess = NULL;
        return false;
    }

    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);
    if (Module32FirstW(modSnapshot, &me32)) {
        g_BaseAddress = (uintptr_t)me32.modBaseAddr;
    }
    CloseHandle(modSnapshot);

    return g_BaseAddress != 0;
}

template<typename T>
static bool ReadMem(uintptr_t address, T* value) {
    SIZE_T bytesRead;
    return ReadProcessMemory(g_hProcess, (LPCVOID)address, value, sizeof(T), &bytesRead) && bytesRead == sizeof(T);
}

static uint32_t ReadLevelID() {
    if (!g_hProcess) return 0;

    uintptr_t pEngine = 0;
    if (!ReadMem(VID_GPO_ENGINE_ADDR, &pEngine) || pEngine == 0) return 0;

    uintptr_t pLevel = 0;
    if (!ReadMem(pEngine + 0xC, &pLevel) || pLevel == 0) return 0;

    uint32_t levelID = 0;
    if (!ReadMem(pLevel + 0x0, &levelID)) return 0;

    return levelID;
}

static int32_t ReadStuffCount() {
    if (!g_hProcess) return 0;

    uintptr_t ptr1 = 0;
    if (!ReadMem(g_BaseAddress + STUFF_PTR_ADDR, &ptr1) || ptr1 == 0) return 0;

    uintptr_t ptr2 = 0;
    if (!ReadMem(ptr1 + 0x8, &ptr2) || ptr2 == 0) return 0;

    int32_t stuffCount = 0;
    if (!ReadMem(ptr2 + 0x188, &stuffCount)) return 0;

    return stuffCount;
}

static void UpdatePresence() {
    uint32_t levelID = ReadLevelID();
    int32_t stuffCount = ReadStuffCount();
    
    if (levelID == g_LastLevelID && stuffCount == g_LastStuffCount && levelID != 0) return;
    g_LastLevelID = levelID;
    g_LastStuffCount = stuffCount;

    switch (levelID) {
        case LEVEL_MENU:        UpdatePresence_Menu(); break;
        case LEVEL_CREDITS:     UpdatePresence_Credits(); break;
        case LEVEL_CUTSCENE:    UpdatePresence_Cutscene(); break;
        case LEVEL_RULES:       UpdatePresence_Rules(); break;
        case LEVEL_BONANZA:     UpdatePresence_Bonanza(); break;
        case LEVEL_WACK:        UpdatePresence_Wack(); break;
        case LEVEL_MOONING:     UpdatePresence_Mooning(); break;
        case LEVEL_SHOP:        UpdatePresence_Shop(); break;
        case LEVEL_BACKWATER:   UpdatePresence_Backwater(); break;
        case LEVEL_PLANE:       UpdatePresence_Plane(); break;
        case LEVEL_BLUES:       UpdatePresence_Blues(); break;
        case LEVEL_NICK:        UpdatePresence_Nick(); break;
        case LEVEL_SUPER:       UpdatePresence_Super(); break;
        case LEVEL_ENGINE:      UpdatePresence_Engine(); break;
        case LEVEL_TILL:        UpdatePresence_Till(); break;
        case LEVEL_INFECTIOUS:  UpdatePresence_Infectious(); break;
        case LEVEL_COUNTRY:     UpdatePresence_Country(); break;
        case LEVEL_STAKES:      UpdatePresence_Stakes(); break;
        case LEVEL_TOTALLY:     UpdatePresence_Totally(); break;
        default:                UpdatePresence_Unknown(); break;
    }
}

static DWORD WINAPI UpdateThread(LPVOID param) {
    while (!FindProcess(L"LyN_f.exe")) {
        Sleep(5000);
    }

    DiscordEventHandlers handlers;
    memset(&handlers, 0, sizeof(handlers));
    handlers.ready = HandleDiscordReady;
    handlers.disconnected = HandleDiscordDisconnected;
    handlers.errored = HandleDiscordError;

    Discord_Initialize(DISCORD_APP_ID, &handlers, 1, NULL);
    g_StartTime = time(NULL);

    while (true) {
        Discord_RunCallbacks();
        if (g_DiscordReady) UpdatePresence();
        Sleep(1000);
    }

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, UpdateThread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        Discord_Shutdown();
        if (g_hProcess) CloseHandle(g_hProcess);
        break;
    }
    return TRUE;
}
