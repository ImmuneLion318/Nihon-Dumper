using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static EyeStepPackage.imports;

namespace EyeStepPackage
{
    public class util
    {
		public const byte c_cdecl		= 0;
		public const byte c_stdcall		= 1;
		public const byte c_fastcall	= 2;
		public const byte c_thiscall	= 3;
		public const byte c_auto		= 4;

		public static List<int> savedRoutines	= new List<int>();
		public static int nothing				= 0;

		public static string[] convs =
		{
			"__cdecl",
			"__stdcall",
			"__fastcall",
			"__thiscall",
			"[auto-generated]"
		};

		public static uint setPageProtect(int address, uint protect, int size = 0x3FF)
		{
			uint old_protect = 0;
			VirtualProtectEx(EyeStep.handle, address, size, protect, ref old_protect);
			return old_protect;
		}

		public static uint getPageProtect(int address)
		{
			MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
			VirtualQueryEx(EyeStep.handle, address, out mbi, 0x2C);
			return mbi.Protect;
		}

		public static void writeByte(int address, byte value)
		{
			byte[] bytes = new byte[sizeof(byte)];
			bytes[0] = value;
			WriteProcessMemory(EyeStep.handle, address, bytes, bytes.Length, ref nothing);
		}

		public static void writeBytes(int address, byte[] bytes, int count = -1)
		{
			WriteProcessMemory(EyeStep.handle, address, bytes, (count == -1) ? bytes.Length : count, ref nothing);
		}

		public static void writeShort(int address, short value)
		{
			byte[] bytes = BitConverter.GetBytes(value);
			WriteProcessMemory(EyeStep.handle, address, bytes, sizeof(short), ref nothing);
		}

		public static void writeUShort(int address, ushort value)
		{
			byte[] bytes = BitConverter.GetBytes(value);
			WriteProcessMemory(EyeStep.handle, address, bytes, sizeof(ushort), ref nothing);
		}

		public static void writeInt(int address, int value)
		{
			byte[] bytes = BitConverter.GetBytes(value);
			WriteProcessMemory(EyeStep.handle, address, bytes, sizeof(int), ref nothing);
		}

		public static void writeUInt(int address, uint value)
		{
			byte[] bytes = BitConverter.GetBytes(value);
			WriteProcessMemory(EyeStep.handle, address, bytes, sizeof(uint), ref nothing);
		}

		public static void writeFloat(int address, float value)
		{
			byte[] bytes = BitConverter.GetBytes(value);
			WriteProcessMemory(EyeStep.handle, address, bytes, sizeof(float), ref nothing);
		}

		public static void writeDouble(int address, double value)
		{
			byte[] bytes = BitConverter.GetBytes(value);
			WriteProcessMemory(EyeStep.handle, address, bytes, sizeof(double), ref nothing);
		}

		public static byte readByte(int address)
		{
			byte[] bytes = new byte[1];
			ReadProcessMemory(EyeStep.handle, address, bytes, sizeof(byte), ref nothing);
			return bytes[0];
		}

		public static byte[] readBytes(int address, int count)
		{
			byte[] bytes = new byte[count];
			ReadProcessMemory(EyeStep.handle, address, bytes, count, ref nothing);
			return bytes;
		}

		public static short readShort(int address)
		{
			byte[] bytes = new byte[sizeof(short)];
			ReadProcessMemory(EyeStep.handle, address, bytes, sizeof(short), ref nothing);
			return BitConverter.ToInt16(bytes, 0);
		}

		public static ushort readUShort(int address)
		{
			byte[] bytes = new byte[sizeof(ushort)];
			ReadProcessMemory(EyeStep.handle, address, bytes, sizeof(ushort), ref nothing);
			return BitConverter.ToUInt16(bytes, 0);
		}

		public static int readInt(int address)
		{
			byte[] bytes = new byte[sizeof(int)];
			ReadProcessMemory(EyeStep.handle, address, bytes, sizeof(int), ref nothing);
			return BitConverter.ToInt32(bytes, 0);
		}

		public static uint readUInt(int address)
		{
			byte[] bytes = new byte[sizeof(uint)];
			ReadProcessMemory(EyeStep.handle, address, bytes, sizeof(uint), ref nothing);
			return BitConverter.ToUInt32(bytes, 0);
		}

		public static float readFloat(int address)
		{
			byte[] bytes = new byte[sizeof(float)];
			ReadProcessMemory(EyeStep.handle, address, bytes, sizeof(float), ref nothing);
			return BitConverter.ToSingle(bytes, 0);
		}

		public static double readDouble(int address)
		{
			byte[] bytes = new byte[sizeof(double)];
			ReadProcessMemory(EyeStep.handle, address, bytes, sizeof(double), ref nothing);
			return BitConverter.ToDouble(bytes, 0);
		}

		public static ulong readQword(int address)
		{
			byte[] bytes = new byte[sizeof(ulong)];
			ReadProcessMemory(EyeStep.handle, address, bytes, sizeof(ulong), ref nothing);
			return BitConverter.ToUInt64(bytes, 0);
		}

		public static void placeJmp(int from, int to)
		{
			int hook_size = 0;
			while (hook_size < 5)
			{
				hook_size += EyeStep.read(from + hook_size).len;
			}

			uint old_protect = setPageProtect(from, PAGE_EXECUTE_READWRITE);

			writeByte(from, 0xE9);
			writeInt(from + 1, (to - from) - 5);

			for (int i = 5; i < hook_size; i++)
			{
				writeByte(from + i, 0x90);
			}

			setPageProtect(from, old_protect);
		}

		public static void placeCall(int from, int to)
		{
			int hook_size = 0;
			while (hook_size < 5)
			{
				hook_size += EyeStep.read(from + hook_size).len;
			}

			uint old_protect = setPageProtect(from, PAGE_EXECUTE_READWRITE);

			writeByte(from, 0xE8);
			writeInt(from + 1, (to - from) - 5);

			for (int i = 5; i < hook_size; i++)
			{
				writeByte(from + i, 0x90);
			}

			setPageProtect(from, old_protect);
		}

		public static void placeTrampoline(int from, int to, int length)
		{
			placeJmp(from, to);
			placeJmp(to + length, from + 5);
		}

		public static int rebase(int address)
		{
			return EyeStep.base_module + address;
		}

		public static int aslr(int address)
		{
			return (EyeStep.base_module + address) - 0x400000;
		}

		public static int raslr(int address)
		{
			return (address - EyeStep.base_module) + 0x400000;
		}

		// can be used on a call or jmp
		public static int getRel(int address)
		{
			return address + 5 + readInt(address + 1);
		}

		// determines if there's a call or jmp at this address
		public static bool isRel(int address)
		{
			return (getRel(address) % 16 == 0);
		}

		// determines if a call instruction is at this address
		public static bool isCall(int address)
		{
			return (
				isRel(address)
			 && getRel(address) > EyeStep.base_module
			 && getRel(address) < EyeStep.base_module + EyeStep.base_module_size
			);
		}

		public static bool isPrologue(int address)
		{
			return (
				// Ensure that it's aligned (helps to filter it immensely)
				(address % 16 == 0)
			  &&
				// Check for 3 different prologues, each with different registers
				((readByte(address) == 0x55 && readUShort(address + 1) == 0xEC8B)
			  || (readByte(address) == 0x53 && readUShort(address + 1) == 0xDC8B)
			  || (readByte(address) == 0x56 && readUShort(address + 1) == 0xF48B))
			);
		}

		public static bool isEpilogue(int address)
		{
			return
			// 1. Check for a pop ebp + retn/ret 
			(
				(readUShort(address - 1) == 0xC35D)
			  ||
				(readUShort(address - 1) == 0xC25D
			  && readUShort(address + 1) >= 0
			  && readUShort(address + 1) % 4 == 0
				)
			) 
			  ||
			// 2. Check for a leave + retn/ret
			(
				(readUShort(address - 1) == 0xC3C9)
			  ||
				(readUShort(address - 1) == 0xC2C9
			  && readUShort(address + 1) >= 0
			  && readUShort(address + 1) % 4 == 0
				)
			);
		}

		// determines whether the address is
		// part of the program's .text/code segment
		public static bool isValidCode(int address)
		{
			return !(readDouble(address) == 0 && readDouble(address + 8) == 0);
		}

		public static int nextPrologue(int address)
		{
			int at = address;

			if (isPrologue(at))
			{
				at += 16;
			}
			else
			{
				at += (at % 16);
			}

			while (!(isPrologue(at) && isValidCode(at)))
			{
				at += 16;
			}

			return at;
		}

		public static int prevPrologue(int address)
		{
			int at = address;

			if (isPrologue(at))
			{
				at -= 16;
			}
			else
			{
				at -= (at % 16);
			}

			while (!(isPrologue(at) && isValidCode(at)))
			{
				at -= 16;
			}

			return at;
		}

		public static int getPrologue(int address)
		{
			return (isPrologue(address)) ? address : prevPrologue(address);
		}

		public static int getEpilogue(int address)
		{
			int next_func = nextPrologue(address);
			int at = next_func;

			// Get the return of this function
			while (!isEpilogue(at))
			{
				at--;
			}

			if (at < address)
			{
				at = next_func;

				if (readByte(at - 1) == 0xCC)
				{
					return at - 1;
				}
			}

			return at;
		}

		public static short getRetn(int address)
		{
			int epilogue = getEpilogue(address);

			if (readByte(epilogue) == 0xC2)
			{
				return readShort(epilogue + 1);
			}

			return 0;
		}

		public static int nextCall(int address, bool location = false, bool func_requires_prologue = false)
		{
			int at = address;

			if (readByte(at) == 0xE8 || readByte(at) == 0xE9)
			{
				at++;
			}

			while (isValidCode(at))
			{
				if ((
					readByte(at) == 0xE8
				 || readByte(at) == 0xE9
					)
				 &&
					isCall(at)
				){
					bool has_prologue = true;

					// check if we need to get the prologue
					if (func_requires_prologue && !isPrologue(getRel(at)))
					{
						has_prologue = false;
					}

					if (has_prologue)
					{
						break;
					}
				}

				at++;
			}

			if (location)
			{
				return at;
			}
			else
			{
				return getRel(at);
			}
		}

		public static int prevCall(int address, bool location = false, bool func_requires_prologue = false)
		{
			int at = address;

			if (readByte(at) == 0xE8 || readByte(at) == 0xE9)
			{
				at--;
			}

			while (isValidCode(at))
			{
				if ((
					readByte(at) == 0xE8
				 || readByte(at) == 0xE9
					)
				 &&
					isCall(at)
				){
					bool has_prologue = true;

					// check if we need to get the prologue
					if (func_requires_prologue && !isPrologue(getRel(at)))
					{
						has_prologue = false;
					}

					if (has_prologue)
					{
						break;
					}
				}

				at--;
			}

			if (location)
			{
				return at;
			}
			else
			{
				return getRel(at);
			}
		}

		public static int nextRef(int start, int func_search, bool prologue = true)
		{
			int at = start;

			while (true)
			{
				if ((
					readByte(at) == 0xE8
				 || readByte(at) == 0xE9
				)
				 && getRel(at) == func_search
				){
					break;
				}

				at++;
			}

			return (prologue) ? getPrologue(at) : at;
		}

		public static int prevRef(int start, int func_search, bool prologue = true)
		{
			int at = start;

			while (true)
			{
				if ((
					readByte(at) == 0xE8
				 || readByte(at) == 0xE9
				) 
				&& getRel(at) == func_search
				){
					break;
				}

				at--;
			}

			return (prologue) ? getPrologue(at) : at;
		}

		public static int nextPointer(int start, int ptr_search, bool prologue)
		{
			int at = start + sizeof(int);

			while (true)
			{
				if (readInt(at) == ptr_search)
				{
					break;
				}
				at++;
			}

			return (prologue) ? getPrologue(at) : at;
		}

		public static int prevPointer(int start, int ptr_search, bool prologue)
		{
			int at = start;

			while (true)
			{
				if (readInt(at) == ptr_search)
				{
					break;
				}
				at--;
			}

			return (prologue) ? getPrologue(at) : at;
		}

		public static List<int> getCalls(int address)
		{
			List<int> calls = new List<int>();

			int at = address;
			int func_end = nextPrologue(at);

			while (at < func_end)
			{
				calls.Add(nextCall(at));
				at = nextCall(at, true) + 5;
			}

			return calls;
		}

		public static List<int> getPointers(int address)
		{
			List<int> pointers = new List<int>();

			int at = address;
			int func_end = nextPrologue(at);

			while (at < func_end)
			{
				var i = EyeStep.read(at);

				if ((i.source().flags & EyeStep.OP_DISP32) == EyeStep.OP_DISP32 && i.source().disp32 % 4 == 0)
				{
					pointers.Add((int)i.source().disp32);
				}
				else if ((i.destination().flags & EyeStep.OP_DISP32) == EyeStep.OP_DISP32 && i.destination().disp32 % 4 == 0)
				{
					pointers.Add((int)i.destination().disp32);
				}

				at += i.len;
			}

			return pointers;
		}

		public static byte getConvention(int func, int n_expected_args)
		{
			byte convention = c_cdecl;

			if (n_expected_args == 0)
			{
				return convention;
			}

			int epilogue = func + 16;
			while (!isPrologue(epilogue) && isValidCode(epilogue))
			{
				epilogue += 16;
			}

			int args = 0;
			int func_start = func;

			while (!isEpilogue(epilogue))
			{
				epilogue--;
			}

			if (readByte(epilogue) == 0xC2)
			{
				convention = c_stdcall;
			}
			else
			{
				convention = c_cdecl;
			}

			// search for the highest ebp offset, which will 
			// indicate the number of args that were pushed
			// on the stack, rather than placed in ECX/EDX
			int at = func_start;
			while (at < epilogue)
			{
				var i = EyeStep.read(at);

				if ((i.flags & EyeStep.OP_SRC_DEST) == EyeStep.OP_SRC_DEST || (i.flags & EyeStep.OP_SINGLE) == EyeStep.OP_SINGLE)
				{
					var src = i.source();
					var dest = i.destination();

					if ((src.flags & EyeStep.OP_R32) == EyeStep.OP_R32 || (src.flags & EyeStep.OP_XMM) == EyeStep.OP_XMM)
					{
						if ((dest.flags & EyeStep.OP_R32) == EyeStep.OP_R32 || (dest.flags & EyeStep.OP_XMM) == EyeStep.OP_XMM)
						{
							if ((dest.flags & EyeStep.OP_IMM8) == EyeStep.OP_IMM8 && dest.reg[0] == EyeStep.R32_EBP && dest.imm8 != 4 && dest.imm8 < 0x7F)
							{
								//System.Windows.Forms.MessageBox.Show(i.data + " -- " + util.raslr(i.address).ToString("X8") + " -- arg offset: " + dest.imm8.ToString("X2"));

								if (dest.imm8 > args)
								{
									args = dest.imm8;
								}
							}
						}
						else if ((src.flags & EyeStep.OP_IMM8) == EyeStep.OP_IMM8 && src.reg[0] == EyeStep.R32_EBP && src.imm8 != 4 && src.imm8 < 0x7F)
						{
							//System.Windows.Forms.MessageBox.Show(i.data + " -- " + util.raslr(i.address).ToString("X8") + " -- arg offset: " + src.imm8.ToString("X2"));

							if (src.imm8 > args)
							{
								args = src.imm8;
							}
						}
					}
				}

				at += i.len;
			}

			// no pushed args were used, but we know there
			// is a 1 or 2 EBP arg difference, so it is either
			// a fastcall or a thiscall
			if (args == 0)
			{
				switch (n_expected_args)
				{
					case 1:
						return c_thiscall;
						break;
					case 2:
						return c_fastcall;
						break;
				}
			}

			args -= 8;
			args = (args / 4) + 1;

			if (args == n_expected_args - 1)
			{
				convention = c_thiscall;
			}
			else if (args == n_expected_args - 2)
			{
				convention = c_fastcall;
			}

			return convention;
		}

		public static byte getConvention(int func)
		{
			function_info info = new function_info();
			info.analyze(func);
			return info.convention;
		}

		public static int createRoutine(int function, byte n_args)
		{
			byte convention = getConvention(function, n_args);

			bool convert_stdcall = false; // personal
			int func = function;
			int size = 0;
			byte[] data = new byte[128];

			var new_func = VirtualAllocEx(EyeStep.handle, 0, 128, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (new_func == 0)
			{
				throw new Exception("Error while allocating memory");
			}

			data[size++] = 0x55; // push ebp

			data[size++] = 0x8B; // mov ebp,esp
			data[size++] = 0xEC;

			if (convention == c_cdecl)
			{
				for (int i = (n_args * 4) + 8; i > 8; i -= 4)
				{
					data[size++] = 0xFF; // push [ebp+??]
					data[size++] = 0x75;
					data[size++] = (byte)(i - 4);
				}
				data[size++] = 0xE8; // call func
				var rel = func - (new_func + size + 4);
				var bytes = BitConverter.GetBytes(rel);
				data[size++] = bytes[0];
				data[size++] = bytes[1];
				data[size++] = bytes[2];
				data[size++] = bytes[3];
				data[size++] = 0x83; // add esp, (n_args * 4)
				data[size++] = 0xC4;
				data[size++] = (byte)(n_args * 4);
			}
			else if (convention == c_stdcall)
			{
				for (int i = (n_args * 4) + 8; i > 8; i -= 4)
				{
					data[size++] = 0xFF; // push [ebp+??]
					data[size++] = 0x75;
					data[size++] = (byte)(i - 4);
				}

				data[size++] = 0xE8; // call func
				var rel = func - (new_func + size + 4);
				var bytes = BitConverter.GetBytes(rel);
				data[size++] = bytes[0];
				data[size++] = bytes[1];
				data[size++] = bytes[2];
				data[size++] = bytes[3];
			}
			else if (convention == c_thiscall)
			{
				data[size++] = 0x51; // push ecx

				for (int i = n_args; i > 1; i--)
				{
					data[size++] = 0xFF; // push [ebp+??]
					data[size++] = 0x75;
					data[size++] = (byte)((i + 1) * 4);
				}

				data[size++] = 0x8B; // mov ecx,[ebp+08]
				data[size++] = 0x4D;
				data[size++] = 0x08;

				data[size++] = 0xE8; // call func
				var rel = func - (new_func + size + 4);
				var bytes = BitConverter.GetBytes(rel);
				data[size++] = bytes[0];
				data[size++] = bytes[1];
				data[size++] = bytes[2];
				data[size++] = bytes[3];

				data[size++] = 0x59; // pop ecx
			}
			else if (convention == c_fastcall)
			{
				data[size++] = 0x51; // push ecx
				data[size++] = 0x52; // push edx

				for (int i = n_args; i > 2; i--)
				{
					data[size++] = 0xFF; // push [ebp+??]
					data[size++] = 0x75;
					data[size++] = (byte)((i + 1) * 4);
				}

				data[size++] = 0x8B; // mov ecx,[ebp+08]
				data[size++] = 0x4D;
				data[size++] = 0x08;

				data[size++] = 0x8B; // mov edx,[ebp+0C]
				data[size++] = 0x55;
				data[size++] = 0x0C;

				data[size++] = 0xE8; // call func
				var rel = func - (new_func + size + 4);
				var bytes = BitConverter.GetBytes(rel);
				data[size++] = bytes[0];
				data[size++] = bytes[1];
				data[size++] = bytes[2];
				data[size++] = bytes[3];

				data[size++] = 0x59; // pop ecx
				data[size++] = 0x5A; // pop edx
			}

			if (!convert_stdcall)
			{
				data[size++] = 0x5D; // pop ebp
				data[size++] = 0xC3; // retn
			}
			else
			{
				data[size++] = 0xC2; // ret xx
				data[size++] = (byte)(n_args * 4);
				data[size++] = 0x00;
			}

			writeBytes(new_func, data, size);
			savedRoutines.Add(new_func);

			return new_func;
		}

		public static string getAnalysis(int func)
		{
			function_info info = new function_info();
			info.analyze(func);
			return info.psuedocode;
		}

		public static void disableFunction(int func)
		{
			uint old_protect = setPageProtect(func, PAGE_EXECUTE_READWRITE);
			if (isPrologue(func))
			{
				short ret = getRetn(func);
				if (ret != 0)
				{
					writeByte(func + 3, 0xC2);
					writeShort(func + 4, ret);
				}
				else
				{
					writeByte(func + 3, 0xC3);
				}
			}
			else
			{
				writeByte(func, 0xC3);
			}
			setPageProtect(func, old_protect);
		}

		public static List<int> debug_r32(int address, byte r32, int offset, int count)
		{
			List<int> results = new List<int>();

			int new_func;
			int vars;
			int signal;
			byte[] old_bytes;
			byte[] bytes;
			int hook_size = 0;

			// Figure out the instructions that may be overwritten
			while (hook_size < 5)
			{
				hook_size += EyeStep.read(address + hook_size).len;
			}

			old_bytes = readBytes(address, hook_size);

			// Allocate memory internally or remotely
			new_func = VirtualAllocEx(EyeStep.handle, 0, 256, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			

			// Places we can store values -- "variables"
			vars = new_func + 128;
			signal = new_func + 124;

			byte[] data = new byte[128];
			int size = 0;

			//
			// Begin writing ASM to the function
			// 

			for (int i = 0; i < hook_size; i++)
			{
				// Place the original bytes first (any that were overwritten)
				data[size++] = old_bytes[i];
			}

			data[size++] = 0x60; // pushad
			data[size++] = 0x50; // push eax

			for (int i = 0; i < count; i++)
			{
				data[size++] = 0x8B; // mov

				if (offset + (count * 4) < 0x80)
				{
					// Byte-sized offset
					data[size++] = (byte)(0x40 + r32); //  eax,[r32 + ??]
					data[size++] = (byte)(offset + (i * 4));
				}
				else
				{
					// DWORD-sized offset
					data[size++] = (byte)(0x80 + r32); // eax,[r32 + ????????]
					bytes = BitConverter.GetBytes(offset + (i * 4));
					data[size++] = bytes[0];
					data[size++] = bytes[1];
					data[size++] = bytes[2];
					data[size++] = bytes[3];
				}

				data[size++] = 0xA3; // mov [vars + x], eax
				bytes = BitConverter.GetBytes(vars + (i * 4));
				data[size++] = bytes[0];
				data[size++] = bytes[1];
				data[size++] = bytes[2];
				data[size++] = bytes[3];
			}

			// update the signal location, meaning
			// the debug is finished
			data[size++] = 0xC7; // mov [signal],00000001
			data[size++] = 0x05;
			bytes = BitConverter.GetBytes(signal);
			data[size++] = bytes[0];
			data[size++] = bytes[1];
			data[size++] = bytes[2];
			data[size++] = bytes[3];
			data[size++] = 0x01;
			data[size++] = 0x00;
			data[size++] = 0x00;
			data[size++] = 0x00;

			data[size++] = 0x58; // pop eax
			data[size++] = 0x61; // popad

			//
			// Function is finished, let's trampoline to it and back
			// 
			writeBytes(new_func, data, size);
			placeTrampoline(address, new_func, size);

			//
			// Wait for the hook to be executed, and 
			// our signal value to be set to 1 (anything non-null)
			//
			while (readInt(signal) == 0)
			{
				System.Threading.Thread.Sleep(10);
			}

			//
			// Dump the register offsets/values into our table
			//
			for (int i = 0; i < count; i++)
			{
				results.Add(readInt(vars + i * 4));
			}

			// Restore protection
			uint old_protect = setPageProtect(address, PAGE_EXECUTE_READWRITE);
			writeBytes(address, old_bytes, hook_size);
			setPageProtect(address, old_protect);

			// Clean up in either mode
			VirtualFreeEx(EyeStep.handle, new_func, 0, MEM_RELEASE);
			
			return results;
		}


		public class function_arg
		{
			public function_arg(int _ebp_offset, int _bits, bool _isCharPointer, int _location)
            {
				ebp_offset = _ebp_offset;
				bits = _bits;
				isCharPointer = _isCharPointer;
				location = _location;
            }

			public int ebp_offset;
			public int bits;
			public bool isCharPointer;
			public int location;
		};

		public class function_info
		{
			public function_info()
            {
				args = new List<function_arg>();
				start_address = 0;
				function_size = 0;
				convention = c_auto;
				return_bits = 0;
				stack_cleanup = 0;
				psuedocode = "";
			}

			public int start_address;
			public int function_size;
			public byte convention;
			public byte return_bits;
			public short stack_cleanup;
			public List<function_arg> args;

			public string psuedocode;

			public void analyze(int func)
            {
				int func_end = getEpilogue(func);

				if (readByte(func_end) == 0xC3)
				{
					stack_cleanup = 0;
					func_end += 1;
				}
				else if (readByte(func_end) == 0xC2)
				{
					stack_cleanup = readShort(func_end + 1);
					func_end += 3;
				}

				// this is the absolute function size
				start_address = func;
				function_size = func_end - func;

				// Identify compiler-generated "strlen" function in memory...
				// we can identify when the compiler generates this
				// simply by checking for a byte signature.
				// This is used to identify const char* args.
				var inlined_strlen = new List<int>();

				for (int i = 0; i < function_size; i++)
				{
					var bytes_strlen = readBytes(start_address + i, 8);

					if (bytes_strlen[0] == 0x8A // mov al,[???]
					 && bytes_strlen[2] >= 0x40 && bytes_strlen[2] < 0x48 // inc ???
					 && bytes_strlen[3] == 0x84 && bytes_strlen[4] == 0xC0 // test al,al
					 && bytes_strlen[5] == 0x75 // jnz
					){
						inlined_strlen.Add(start_address + i);
						i += 8;
					}
				}

				bool ecx_set = false;
				bool edx_set = false;
				int at = func;

				var return_value = new EyeStep.operand();
				var ebp_args = new List<int>();

				while (at < func_end)
				{
					var i = EyeStep.read(at);

					//printf("%s\n", i.data);

					var src = i.source();
					var dest = i.destination();

					string opcode = "";
					opcode += i.data;

					// not set yet?
					if (convention == c_auto)
					{
						// set the calling convention to the
						// function's return
						if (opcode.Contains("retn"))
						{
							stack_cleanup = 0;
							convention = c_cdecl;
						}
						else if (opcode.Contains("ret "))
						{
							stack_cleanup = readShort(i.address + 1);
							convention = c_stdcall;
						}
					}

					// does the source operand use a register?
					if (src.reg.Count > 0)
					{
						// mov [ebp+08], ???
						// mov [ebp+0C], ???
						// . . .
						if ((src.flags & EyeStep.OP_R32) == EyeStep.OP_R32 && src.reg[0] == EyeStep.R32_EBP && src.imm8 >= 8 && src.imm8 < 0x40)
						{
							bool found = false;

							foreach (int arg in ebp_args)
							{
								if (src.imm8 == arg)
								{
									found = true;
								}
							}

							if (!found)
							{
								// Append args from EBP
								ebp_args.Add(src.imm8);
								args.Add(new function_arg(src.imm8, 32, false, at));
							}
						}

						// Figure out what the very last thing is
						// that gets placed into EAX ( the return value )
						// mov eax, ???
						// or eax, ???
						if (src.reg[0] == EyeStep.R32_EAX)
						{
							if (opcode.Contains("mov ")
							 || opcode.Contains("or ")
								) {
								return_value = dest;
							}
						} else if (src.reg[0] == EyeStep.R32_ECX)
						{
							ecx_set = true;
						}
						else if (src.reg[0] == EyeStep.R32_EDX)
						{
							convention = c_auto; // let it be determined by the function return
							edx_set = true;
							break;
						}

						// does the destination operand use a register?
						if (dest.reg.Count > 0)
						{
							// mov ???, [ebp+08]
							// mov ???, [ebp+0C]
							// . . .
							if ((dest.flags & EyeStep.OP_R32) == EyeStep.OP_R32 && dest.reg[0] == EyeStep.R32_EBP && dest.imm8 >= 8 && dest.imm8 < 0x40)
							{
								bool found = false;

								foreach (int arg in ebp_args)
								{
									if (dest.imm8 == arg)
									{
										found = true;
									}
								}

								if (!found)
								{
									// Append args from EBP
									ebp_args.Add(dest.imm8);
									args.Add(new function_arg(dest.imm8, 32, false, at));
								}
							}

							// instruction does not use ecx or edx in both operands.
							if ((src.reg[0] == EyeStep.R32_EDX && dest.reg[0] == EyeStep.R32_EDX)
							 || (src.reg[0] == EyeStep.R32_ECX && dest.reg[0] == EyeStep.R32_ECX)
							){
								// an instruction was used with `ecx,ecx`
								// or `edx,edx`.
								// We may have to do something about this here...
								/*
								if (opcode.find("test ") != std::string::npos
									&& src.reg[0] == R32_EDX
									&& dest.reg[0] == R32_EDX
									&& !edx_set
									) {
									convention = c_fastcall;
								}
								else if (opcode.find("test ") != std::string::npos
									&& src.reg[0] == R32_ECX
									&& dest.reg[0] == R32_ECX
									&& !ecx_set
									) {
									convention = c_thiscall;
								}
								*/
							}
							else 
							{
								// EDX was used in the destination operand, before
								// it was allocated. It must be a fastcall.
								if (dest.reg[0] == EyeStep.R32_EDX && !edx_set)
								{
									convention = c_fastcall;
									break;
								}
								// ECX was used in the destination operand, before
								// it was allocated. It must be a thiscall.
								else if (dest.reg[0] == EyeStep.R32_ECX && !ecx_set)
								{
									if (convention != c_fastcall)
									{
										convention = c_thiscall;
									}
								}
							}
						}
						else {
							// SINGLE OPERAND INSTRUCTION
							// Check if it pops ECX or pops EDX
							if (opcode.Contains("pop "))
							{
								if (src.reg[0] == EyeStep.R32_ECX)
								{
									ecx_set = false;
								}
								else if (src.reg[0] == EyeStep.R32_EDX)
								{
									edx_set = false;
								}
							}
							// Check if it pushes ECX or pushes EDX
							else if (opcode.Contains("push "))
							{
								if (src.reg[0] == EyeStep.R32_ECX)
								{
									ecx_set = true; // ECX HAS been pushed, meaning it cannot be a thiscall
								}
								else if (src.reg[0] == EyeStep.R32_EDX)
								{
									edx_set = true; // EDX HAS been pushed meaning it cannot be a fastcall
								}
							}
						}
					}

					at += i.len;
				}

				// append the args from ECX/EDX to the args
				// identified from offsets of EBP.
				if (convention == c_thiscall)
					args.Add(new function_arg(0, 32, false, 0));
				else if (convention == c_fastcall)
				{
					args.Add(new function_arg(0, 32, false, 0));
					args.Add(new function_arg(0, 32, false, 0));
				}
				else if (convention == c_auto)
				{
					// set the default calling convention if it could not be identified...
					if (stack_cleanup == 0)
						convention = c_cdecl;
					else
						convention = c_stdcall;
				}

				// adjust args...check for args that were used
				// with a compiler-generated `strlen()` and identify
				// them as a const char* arg.
				if (inlined_strlen.Count > 0)
				{
					foreach (int r in inlined_strlen)
					{
						for (int i = args.Count - 1; i >= 0; i--)
						{
							if (args[i].location < r)
							{
								args[i].isCharPointer = true;
								break;
							}
						}
					}
				}

				// Start writing to the psuedocode
				// (we can start with the return value)
				if ((return_value.flags & EyeStep.OP_DISP8) == EyeStep.OP_DISP8 || (return_value.flags & EyeStep.OP_R8) == EyeStep.OP_R8)
				{
					psuedocode += "bool "; // chances are it's a bool value
					return_bits = sizeof(byte);
				}
				else if ((return_value.flags & EyeStep.OP_DISP16) == EyeStep.OP_DISP16 || (return_value.flags & EyeStep.OP_R16) == EyeStep.OP_R16)
				{
					psuedocode += "short ";
					return_bits = sizeof(short);
				}
				else if ((return_value.flags & EyeStep.OP_DISP32) == EyeStep.OP_DISP32 || (return_value.flags & EyeStep.OP_R32) == EyeStep.OP_R32)
				{
					psuedocode += "int ";
					return_bits = sizeof(int);
				}
				else {
					// To-do... Analyse when ESP is altered
					// with push and pop,
					// add esp and sub esp.
					// The left over amount (if it's 4 bytes)
					// will tell us whether the function returns an
					// int or not.
					psuedocode += "int ";
					return_bits = sizeof(int);
				}

				psuedocode += convs[convention];
				psuedocode += " ";
				psuedocode += start_address.ToString("X8");
				psuedocode += "(";

				for (int i = 0; i < args.Count; i++)
				{
					if (args[i].isCharPointer)
					{
						psuedocode += "const char*";
					}
					else if (args[i].bits == 8)
					{
						psuedocode += "byte";
					}
					else if (args[i].bits == 16)
					{
						psuedocode += "short";
					}
					else if (args[i].bits == 32)
					{
						psuedocode += "int";
					}

					psuedocode += " a";
					psuedocode += Convert.ToString(i + 1);

					if (i < args.Count - 1)
					{
						psuedocode += ", ";
					}
				}

				psuedocode += ")";
            }
		};


		public static int inject_function(int address, string code)
		{
			int start = (address != 0) ? address : VirtualAllocEx(EyeStep.handle, 0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);



			return start;
		}
	}

    public class scanner
    {
		public enum scanchecks
		{
			byte_equal,
			word_equal,
			int_equal,
			byte_notequal,
			word_notequal,
			int_notequal
		};

		public struct scancheck
		{
			public scancheck(scanchecks _type, int _offset, UInt32 _small)
            {
				type = _type;
				offset = _offset;
				small = _small;
				large = 0;
            }

			public scanchecks type;
			public int offset;
			public UInt32 small;
			public UInt64 large;
		};

		static bool compare_bytes(byte[] bytes, ref int at, byte[] aob, char[] mask, int size)
		{
			for (int i = 0; i < size; i++)
            {
				if (mask[i] == '.' && bytes[at + i] != aob[i])
                {
					return false;
                }
            }
			return true;
		}

		public static List<int> scan(string aob, bool code = true, int align = 1, int endresult = 0, scancheck[] checks = null)
		{
			List<int> results = new List<int>();

			MEMORY_BASIC_INFORMATION mbi;

			int start;
			int end;

			byte[] pattern = new byte[128];
			char[] mask = new char[128];

			// reinterprets the AOB string as a string mask
			for (int i = 0, j = 0; i < aob.Length; i++)
			{
				if (aob[i] == 0x20)
				{
					continue;
				}

				char[] x = new char[2];
				x[0] = aob[i];
				x[1] = aob[1 + i++];

				if (x[0] == '?' && x[1] == '?')
				{
					pattern[j] = 0;
					mask[j++] = '?';
				}
				else
				{
					// convert 2 chars to byte
					int id = 0;
					int n = 0;

					convert:
					if (x[id] > 0x60) n = x[id] - 0x57; // n = A-F (10-16)
					else if (x[id] > 0x40) n = x[id] - 0x37; // n = a-f (10-16)
					else if (x[id] >= 0x30) n = x[id] - 0x30; // number chars

					if (id != 0)
						pattern[j] += (byte)n;
					else
					{
						id++;
						pattern[j] += (byte)(n * 16);
						goto convert;
					}

					mask[j++] = '.';
				}
			}

			if (!code)
			{
				// Restrict the scan to virtual memory
				start = EyeStep.base_module + EyeStep.base_module_size;
				end = 0x3FFFFFFF;
			}
			else
			{
				start = EyeStep.base_module;
				end = EyeStep.base_module + EyeStep.base_module_size;
			}

			while (start < end)
			{
				VirtualQueryEx(EyeStep.handle, start, out mbi, 0x2C);
				
				if (mbi.BaseAddress != 0)
				{
					// Make sure the memory is committed, matches our protection, and isn't PAGE_GUARD.
					if ((mbi.State & MEM_COMMIT) == MEM_COMMIT && (mbi.Protect & PAGE_NOACCESS) != PAGE_NOACCESS && (mbi.Protect & PAGE_NOCACHE) != PAGE_NOCACHE && (mbi.Protect & PAGE_GUARD) != PAGE_GUARD)
					{
						var bytes = util.readBytes(start, mbi.RegionSize);

						// Scan all the memory in the region.
						for (int i = 0; i < mbi.RegionSize; i += align)
						{
							if (compare_bytes(bytes, ref i, pattern, mask, mask.Length))
							{
								int result = start + i;

								if (checks == null)
									results.Add(result);
								else
								{
									// Go through a series of extra checks,
									// make sure all are passed before it's a valid result
									int checks_pass = 0;

									foreach (scancheck check in checks)
									{
										switch (check.type)
										{
										case scanchecks.byte_equal:
											if (bytes[i + check.offset] == check.small) checks_pass++;
											break;
										case scanchecks.word_equal:
											if (BitConverter.ToUInt16(bytes, i + check.offset) == check.small) checks_pass++;
											break;
										case scanchecks.int_equal:
											if (BitConverter.ToUInt32(bytes, i + check.offset) == check.small) checks_pass++;
											break;
										case scanchecks.byte_notequal:
											if (bytes[i + check.offset] != check.small) checks_pass++;
											break;
										case scanchecks.word_notequal:
											if (BitConverter.ToUInt16(bytes, i + check.offset) != check.small) checks_pass++;
											break;
										case scanchecks.int_notequal:
											if (BitConverter.ToUInt32(bytes, i + check.offset) != check.small) checks_pass++;
											break;
										}
									}

									if (checks_pass == checks.Length)
									{
										results.Add(result);
									}
								}
								if (endresult > 0 && results.Count >= endresult)
								{
									break;
								}
							}
						}
					}

					//System.Windows.Forms.MessageBox.Show(start.ToString("X8"));
					// Move onto the next region of memory.
					start += mbi.RegionSize;
				}
			}

			return results;
		}

		// converts a string like "Test" to an AOB string "54 65 73 74"
		public static string aobstring(string str)
		{
			string aob = "";

			for (int i = 0; i < str.Length; i++)
			{
				var b_char = (byte)str[i];
				aob += EyeStep.to_str(b_char);

				if (i < str.Length - 1)
				{
					aob += " ";
				}
			}

			return aob;
		}

		// converts a result to an AOB string
		// for example 0x110CBED0 --> "D0 BE 0C 11"
		public static string ptrstring(int ptr)
		{
			string aob = "";

			byte[] bytes = BitConverter.GetBytes(ptr);
			aob += EyeStep.to_str(bytes[0]);
			aob += EyeStep.to_str(bytes[1]);
			aob += EyeStep.to_str(bytes[2]);
			aob += EyeStep.to_str(bytes[3]);

			return aob;
		}

		public static List<int> scan_xrefs(string str, int nresult = 0)
		{
			List<int> result_list = scan(aobstring(str), true, 4, nresult);

			if (result_list.Count > 0)
			{
				return scan(ptrstring(result_list.Last()));
			}
			else
			{
				throw new Exception("No results found for string");
			}
		}

		public static List<int> scan_xrefs(int func)
		{
			List<int> results = new List<int>();

			MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();

			int start = EyeStep.base_module;
			int end = EyeStep.base_module + EyeStep.base_module_size;

			while (start < end)
			{
				VirtualQueryEx(EyeStep.handle, start, out mbi, 0x2C);
				
				if (mbi.Protect == PAGE_EXECUTE_READ)
				{
					byte[] bytes = util.readBytes(start, mbi.RegionSize);

					for (int at = 0; at < mbi.RegionSize; at++)
					{
						if (bytes[at] == 0xE8 || bytes[at] == 0xE9)
						{
							if (util.getRel(start + at) == func)
							{
								results.Add(start + at);
							}
						}
					}
				}

				start += mbi.RegionSize;
			}

			return results;
		}
	}
}
