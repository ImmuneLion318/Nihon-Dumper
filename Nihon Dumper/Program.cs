using System;
using System.Diagnostics;
using System.Linq;
using EyeStepPackage;
using System.Threading;
using System.Net;

namespace NihonDumper
{
    public class Program
    {
        static Stopwatch Watch = new Stopwatch();
        static WebClient WebClient = new WebClient();

        public static string Gettop_Address = "55 8B EC 8B 4D 08 8B 41 ?? 2B 41 ?? C1 F8 04 5D"; 
        public static string Index2adr_Address = "55 8B EC 8B 55 ?? 81 FA F0 D8 FF FF 7E 0F ?? ?? ?? ?? E2 04 03 51 10 8B C2 5D C2 08 00 8B 45 08"; 
        public static string RetCheck_Address = "55 8B EC 64 A1 00 00 00 00 6A ?? 68 E8 ?? ?? ?? ?? 64 89 25 00 00 00 00 83 EC ?? 53 56 57 6A ?? E9 ?? ?? ?? ??"; 
        public static string Deserialize_Address = "55 8B EC 6A FF 68 70 ?? ?? ?? ?? A1 00 00 00 00 50 64 89 25 00 00 00 00 81 EC 58 01 00 00 56 57";
        public static string GetDataModel_Address = "55 8B EC 64 A1 00 00 00 00 6A FF 68 ?? ?? ?? ?? 50 64 89 25 00 00 00 00 83 EC ?? 80 3D 70 51 5E";

        static void Main(string[] args)
        {
            string Watermark = @" 
   _   _ _ _                  ______                                 
  | \ | (_) |                 |  _  \                                
  |  \| |_| |__   ___  _ __   | | | |_   _ _ __ ___  _ __   ___ _ __ 
  | . ` | | '_ \ / _ \| '_ \  | | | | | | | '_ ` _ \| '_ \ / _ \ '__|
  | |\  | | | | | (_) | | | | | |/ /| |_| | | | | | | |_) |  __/ |   
  \_| \_/_|_| |_|\___/|_| |_| |___/  \__,_|_| |_| |_| .__/ \___|_|   
                                                    | |              
                                                    |_|              ";

            string Credits = "  Nihon Dumper Made By ImmuneLion318#0001 \n  " + "Thanks To DeadLocust#1757 For Help Making This Dumper \n";

            Console.Title = "Nihon Dumper";

            Console.WindowWidth = 120;
            Console.WindowHeight = 30;
            Console.SetWindowPosition(0, 0);

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(Watermark);
            Text.Write(Credits);

            Console.ForegroundColor = ConsoleColor.White;
            Text.Write("  Waiting For Roblox... ");
            Thread.Sleep(1500);

            Process[] DetectingRoblox = Process.GetProcessesByName("RobloxPlayerBeta");
            if (DetectingRoblox.Length > 0)
            {
                foreach (var RobloxFound in Process.GetProcessesByName("RobloxPlayerBeta"))
                {
                    string RobloxVersion = WebClient.DownloadString("http://setup.roblox.com/version");

                    Console.ForegroundColor = ConsoleColor.Red;
                    Text.Write("\n  Roblox Found, Dumping Addresses");

                    EyeStep.open("RobloxPlayerBeta.exe");

                    Watch.Start();

                    var RandomInstruction = EyeStep.read(EyeStep.base_module + 0x1027).data;

                    var Deserializer = util.getPrologue(scanner.scan_xrefs(": bytecode").Last());

                    var Lua = util.getPrologue(scanner.scan_xrefs("The metatable is locked", 1)[1]);
                    var LuaCalls = util.getCalls(util.nextCall(Lua));

                    var Index2adr = util.nextCall(LuaCalls[0]);
                    var Index2AdrCalls = scanner.scan_xrefs(Index2adr);

                    var LuaC = util.getPrologue(scanner.scan_xrefs("The metatable is locked", 0)[0]);
                    var LuaCCalls = util.getCalls(util.nextCall(LuaC));

                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n  Lua Addresses");
                    Console.ForegroundColor = ConsoleColor.White;
                    LogFunction("  Lua GetField", util.raslr(LuaCalls[0]));
                    LogFunction("  Lua Type", util.raslr(LuaCalls[1]));
                    LogFunction("  Lua Settop", util.raslr(LuaCalls[2]));
                    LogFunction("  Lua CreateTable", util.raslr(LuaCalls[3]));
                    LogFunction("  Lua PushValue", util.raslr(LuaCalls[4]));
                    LogFunction("  Lua SetField", util.raslr(LuaCalls[5]));
                    LogFunction("  Lua RawValue", util.raslr(util.getPrologue(Index2AdrCalls[0])));
                    LogFunction("  Lua GetFenv", util.raslr(util.getPrologue(Index2AdrCalls[1])));
                    LogFunction("  Lua GetField", util.raslr(util.getPrologue(Index2AdrCalls[2])));
                    LogFunction("  Lua GetMetaTable", util.raslr(util.getPrologue(Index2AdrCalls[3])));
                    LogFunction("  Lua GetTable", util.raslr(util.getPrologue(Index2AdrCalls[4])));
                    LogFunction("  Lua GetUpValue", util.raslr(util.getPrologue(Index2AdrCalls[5])));
                    LogFunction("  Lua Insert", util.raslr(util.getPrologue(Index2AdrCalls[6])));
                    LogFunction("  Lua IsUserData", util.raslr(util.getPrologue(Index2AdrCalls[7])));
                    LogFunction("  Lua IsCFunction", util.raslr(util.getPrologue(Index2AdrCalls[8])));
                    LogFunction("  Lua IsNumber", util.raslr(util.getPrologue(Index2AdrCalls[9])));
                    LogFunction("  Lua IsString", util.raslr(util.getPrologue(Index2AdrCalls[10])));
                    LogFunction("  Lua LessThan", util.raslr(util.getPrologue(Index2AdrCalls[11])));
                    LogFunction("  Lua Next", util.raslr(util.getPrologue(Index2AdrCalls[13])));
                    LogFunction("  Lua Objlen", util.raslr(util.getPrologue(Index2AdrCalls[14])));
                    LogFunction("  Lua PCall", util.raslr(util.getPrologue(Index2AdrCalls[15])));
                    LogFunction("  Lua PushValue", util.raslr(util.getPrologue(Index2AdrCalls[16])));
                    LogFunction("  Lua RawEqual", util.raslr(util.getPrologue(Index2AdrCalls[17])));
                    LogFunction("  Lua RawGet", util.raslr(util.getPrologue(Index2AdrCalls[19])));
                    LogFunction("  Lua RawGeti", util.raslr(util.getPrologue(Index2AdrCalls[21])));
                    LogFunction("  Lua RawSet", util.raslr(util.getPrologue(Index2AdrCalls[22])));
                    LogFunction("  Lua RawSeti", util.raslr(util.getPrologue(Index2AdrCalls[23])));
                    LogFunction("  Lua Remove", util.raslr(util.getPrologue(Index2AdrCalls[24])));
                    LogFunction("  Lua Replace", util.raslr(util.getPrologue(Index2AdrCalls[25])));
                    LogFunction("  Lua SetFenv", util.raslr(util.getPrologue(Index2AdrCalls[26])));
                    LogFunction("  Lua SetMetaTable", util.raslr(util.getPrologue(Index2AdrCalls[28])));
                    LogFunction("  Lua SetReadOnly", util.raslr(util.getPrologue(Index2AdrCalls[29])));
                    LogFunction("  Lua SetSafeEnv", util.raslr(util.getPrologue(Index2AdrCalls[30])));
                    LogFunction("  Lua SetTable", util.raslr(util.getPrologue(Index2AdrCalls[31])));
                    LogFunction("  Lua SetUpValue", util.raslr(util.getPrologue(Index2AdrCalls[32])));
                    LogFunction("  Lua ToBoolean", util.raslr(util.getPrologue(Index2AdrCalls[33])));
                    LogFunction("  Lua ToInteger", util.raslr(util.getPrologue(Index2AdrCalls[34])));
                    LogFunction("  Lua TolString", util.raslr(util.getPrologue(Index2AdrCalls[35])));
                    LogFunction("  Lua ToNumber", util.raslr(util.getPrologue(Index2AdrCalls[37])));
                    LogFunction("  Lua ToPointer", util.raslr(util.getPrologue(Index2AdrCalls[38])));
                    LogFunction("  Lua ToString", util.raslr(util.getPrologue(Index2AdrCalls[40])));
                    LogFunction("  Lua ToThread", util.raslr(util.getPrologue(Index2AdrCalls[42])));
                    LogFunction("  Lua ToUnSignedX", util.raslr(util.getPrologue(Index2AdrCalls[43])));
                    LogFunction("  Lua ToUserData", util.raslr(util.getPrologue(Index2AdrCalls[44])));

                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n  Proto Structs");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine("  Coming Soon...");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n  LuaU Addresses");
                    Console.ForegroundColor = ConsoleColor.White;
                    LogFunction("  LuaU Deserializer", util.raslr(Deserializer));
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n  LuaC Addresses");
                    Console.ForegroundColor = ConsoleColor.White;
                    LogFunction("  LuaC Step", util.raslr(LuaCCalls[1]));
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n  LuaS Addresses");
                    Console.ForegroundColor = ConsoleColor.White;
                    LogFunction("  LuaS Newlstr ", util.raslr(LuaCCalls[2]));
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n  Functions");
                    Console.ForegroundColor = ConsoleColor.White;
                    LogFunction("  Retcheck", util.raslr(LuaCCalls[3]));
                    LogFunction("  Index2Adr", util.raslr(Index2adr));
                    Console.WriteLine(Environment.NewLine);

                    Watch.Stop();

                    Console.ForegroundColor = ConsoleColor.White;
                    Text.Write("  Roblox " + RobloxVersion);
                    Text.Write("  Scanned " + AddyCount + " Addresses" + "Took " + Watch.ElapsedMilliseconds + "ms");
                    Text.Write("  Press Enter To Exit...");
                    Console.ReadLine();
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Text.Write("  Roblox Not Found... Closing Application ");
                Thread.Sleep(2000);
                Environment.Exit(0);
                Console.ReadLine();
            }
        }

        public static int AddyCount;
        static void LogFunction(string Fname, int Address)
        {
            int Space = 20 - Fname.Length;

            Console.Write(Fname);
            for (int i = 0; i < Space; i++)
            {
                Console.Write(" ");
            }
            Console.Write(": 0x" + Address.ToString("X8").Remove(0, 1) + " " + GetConvention(Address) + Environment.NewLine);
            AddyCount = AddyCount + 1;
        }
        public static string GetConvention(int Function)
        {
            byte Call = util.getConvention(Function);
            if (Call == 0)
            {
                return "__cdecl";
            }
            else if (Call == 1)
            {
                return "__stdcall";
            }
            else if (Call == 2)
            {
                return "__fastcall";
            }
            else if (Call == 3)
            {
                return "__thiscall";
            }
            else if (Call == 4)
            {
                return "[auto-generated]";
            }
            else
            {
                return "";
            }
        }

        public static class Text
        {
            public static void Write(string Text)
            {
                string Content = $"{Text}\n";
                for (int l = 0; l < Content.Length; l++)
                {
                    Thread.Sleep(20);
                    Console.Write(Content[l]);
                }
            }
        }
    }
}
