using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Timers;

namespace NihonDumper.Extensions
{
    public class ProcessWatcher : IDisposable
    {
        public delegate void CreatedDelegate(Process Proc);
        public event CreatedDelegate Created;

        private Timer Timer { get; } = new();
        private string ProcessName;
        private Process[] Processes;
        private Process Process;

        private bool IsDisposed = false;
        public double Interval { get; set; }
        public ProcessWatcher(string ProcessName) => this.ProcessName = ProcessName;

        public void Init()
        {
            this.Timer.Interval = Interval;
            this.Timer.Elapsed += Timer_Elapsed;
            this.Timer.Start();
        }

        protected virtual void Timer_Elapsed(object sender, ElapsedEventArgs e)
        {
            Processes = Process.GetProcessesByName(this.ProcessName);
            if (Processes.Length < 1) return;

            this.OnProcessCreated(Processes[0]);
            Created?.Invoke(Processes[0]);
        }

        protected virtual void OnProcessCreated(Process Process)
        {
            this.Timer.Stop();
            this.Process = Process;
            Process.EnableRaisingEvents = true;

            Process.Exited += (Sender, Handler) => Timer.Start();
        }

        public void Dispose()
        {
            if (IsDisposed) return;

            Timer.Dispose();
            IsDisposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
