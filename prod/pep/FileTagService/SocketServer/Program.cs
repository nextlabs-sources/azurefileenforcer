using System;
using System.Threading;

#if DEBUG
using log4net;
using System.Diagnostics;
#endif

namespace SocketServer
{
    class ServerThread
    {
        private Thread thread;
        IOCPServer m_iocpServer;
        public ServerThread()
        {
            thread = new Thread(new ThreadStart(Process));
        }
        public void Run()
        {
            thread.Start();
        }
        public void Stop()
        {
            m_iocpServer.Stop();
            thread.Join();
        }

        private void Process()
        {
            //m_iocpServer = new IOCPServer(6666);
            m_iocpServer = new IOCPServer();
            m_iocpServer.Start();
        }
    }

    class Program
    {
        static private ServerThread m_theServer;
        public void ThreadPoolCallBack(Object threadContext)
        {
        }
        static void Main(string[] args)
        {
#if DEBUG
            string strname = System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.ToString() + "." + System.Reflection.MethodBase.GetCurrentMethod().Name;
            ILog theLog = log4net.LogManager.GetLogger(strname);
            using (Process p = Process.GetCurrentProcess())
            {
                //the process priority can be inherited by sub process and thread.
                p.PriorityClass = ProcessPriorityClass.Idle;
                theLog.Debug($"Base priority : {p.BasePriority}, Priority class : {p.PriorityClass}.");
            }
#endif
            m_theServer = new ServerThread();
            m_theServer.Run();
            while(true)
            {
                string input = Console.ReadLine();
                if(string.Equals(input,"quit"))
                {
                    m_theServer.Stop();
                    break;
                }
            }
        }
    }
}
