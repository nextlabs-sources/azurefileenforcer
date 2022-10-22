using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Threading;
using System.Net;
using System.Net.Sockets;

namespace ContentService
{
    class ServerThread
    {
        private AutoResetEvent exitEvent;
        private Thread thread;
        public ServerThread()
        {
            exitEvent = new AutoResetEvent(false);
            thread = new Thread(new ThreadStart(Process));
        }
        public void Run()
        {
            thread.Start();
        }
        public void Stop()
        {
            exitEvent.Set();
            thread.Join();
        }

        // recive data
        public void ThreadPoolCallBack(Object threadContext)
        {
        }
        private void Process()
        {

            //初始化IP地址  
            IPAddress local = IPAddress.Parse("192.168.5.187");
            IPEndPoint iep = new IPEndPoint(local, 13000);
            Socket server = new Socket(AddressFamily.InterNetwork, SocketType.Stream,ProtocolType.Tcp);
            //将套接字与本地终结点绑定  
            server.Bind(iep);
            //在本地13000端口号上进行监听  
            server.Listen(20);
            Console.WriteLine("等待客户机进行连接......");
            while (true)
            {
                //得到包含客户端信息的套接字  
                Socket client = server.Accept();
                ThreadPool.QueueUserWorkItem(ThreadPoolCallBack, client);
                ThreadPool.SetMaxThreads(3, 3);
                if (exitEvent.WaitOne(1))
                {
                    break;
                }
            }
        }
    }

    public partial class SocketServ : ServiceBase
    {
        private ServerThread m_theServer;
        public SocketServ()
        {
            InitializeComponent();
        }

        public static void ThreadSrv(Object obj)
        {

        }

        protected override void OnStart(string[] args)
        {
            FileStream fs = new FileStream(@"E:\work\tempdata\xx.txt", FileMode.OpenOrCreate, FileAccess.Write);
            StreamWriter sw = new StreamWriter(fs);
            sw.BaseStream.Seek(0, SeekOrigin.End);
            sw.WriteLine("WindowsService: Service Started" + DateTime.Now.ToString() + "\n");

            sw.Flush();
            sw.Close();
            fs.Close();

            m_theServer = new ServerThread();
            m_theServer.Run();

            //ThreadPool.QueueUserWorkItem();
        }

        protected override void OnStop()
        {
            FileStream fs = new FileStream(@"E:\work\tempdata\xx.txt", FileMode.OpenOrCreate, FileAccess.Write);
            StreamWriter sw = new StreamWriter(fs);
            sw.BaseStream.Seek(0, SeekOrigin.End);
            sw.WriteLine("WindowsService: Service Stopped" + DateTime.Now.ToString() + "\n");
            sw.Flush();
            sw.Close();
            fs.Close();

            m_theServer.Stop();

        }
    }
}
