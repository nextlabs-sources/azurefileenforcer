using System.ServiceProcess;
using System.Diagnostics;

#if DEBUG
using log4net;
#endif

namespace SocketServiceWrapper
{
    static class Program
    {

#if DEBUG
        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        public static extern void OutputDebugString(string message);
#endif

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        static void Main()
        {
#if DEBUG
            string strname = System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.ToString() + "." + System.Reflection.MethodBase.GetCurrentMethod().Name;
            ILog theLog = log4net.LogManager.GetLogger(strname);
#endif
            using (Process p = Process.GetCurrentProcess())
            {
                //the process priority can be inherited by sub process and thread.
                p.PriorityClass = ProcessPriorityClass.Idle;
#if DEBUG
                theLog.Debug($"Base priority : {p.BasePriority}, Priority class  : {p.PriorityClass}.");
#endif
            }
            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[]
            {
                new SocketService()
            };
            ServiceBase.Run(ServicesToRun);
        }
    }
}
