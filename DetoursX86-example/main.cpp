#include <Windows.h>
#include <iostream>

#include "detours.h"
#include "sigscan.h"

#pragma comment(lib, "detours.lib")


DWORD AddressOfSum = 0;
// template for the original function
typedef int (__cdecl *sum)(int x, int y);

int __cdecl HookSum(int x, int y)
{
	std::cout << "your program has been hacked! " << std::endl;
	std::cout << "x: " << x << std::endl;
	std::cout << "y: " << y << std::endl;
	sum originalSum = (sum)AddressOfSum;
	return originalSum(x, y);
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	// store the address of sum() in testprogram.exe here.

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		// We will use signature scanning to find the function that we want to hook
		// we will find the function in IDA pro and create a signature from it:

		SigScan Scanner;

		// testprogram.exe is the name of the main module in our target process
		AddressOfSum = Scanner.FindPattern("target.exe",
			"\x55\x8b\xec\x81\xec\x00\x00\x00\x00\x53\x56\x57\x8d\xbd\x00\x00\x00\x00\xb9\x00\x00\x00\x00\xb8\x00\x00\x00\x00\xf3\x00\xb9\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x8b\x45",
			"xxxxx????xxxxx????x????x????x?x????x????xx");

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		// this will hook the function
		DetourAttach(&(LPVOID&)AddressOfSum, &HookSum);

		DetourTransactionCommit();
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		// unhook
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		// this will hook the function
		DetourDetach(&(LPVOID&)AddressOfSum, &HookSum);

		DetourTransactionCommit();
	}
	return TRUE;
}