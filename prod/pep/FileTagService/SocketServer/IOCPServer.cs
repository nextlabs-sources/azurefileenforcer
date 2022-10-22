using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Net;
using System.Threading;
using System.Collections;
using System.Net.NetworkInformation;
using log4net;

namespace SocketServer
{
    /// <summary>
    /// IOCP SOCKET Server
    /// </summary>
    public class IOCPServer
    {
        private class WorkItem
        {
            public byte[] m_szbuf;
            public int m_nBufLen;
            public EndPoint m_csocket;

            public WorkItem(int nLen, byte[] szbuf, EndPoint client)
            {
                m_nBufLen = nLen;
                m_szbuf = new byte[m_nBufLen];
                Array.Copy(szbuf, m_szbuf, nLen);
                m_csocket = client;
            }
        }

        static private ManualResetEvent m_bStop = new ManualResetEvent(false);
        static private Socket m_srvSocket = null;
        static private object m_objLock = new object();    // task list object
        static private List<WorkItem> m_theTasks = new List<WorkItem>();
        private int m_nPort = 6666;
        private int[] m_arrPort = { 6666, 6667, 6668, 6669, 6670, 6671, 6672, 6673, 6674, 6675 };
        static private int m_nRecvBufLen = 2048;

        // actually, 2 is enough for performance
        private int m_nWorkThreadNum = 2;

        // just for debug ,for release, set it to false
        private static readonly bool m_gDebug = false;

        public IOCPServer()
        {
            string strname = System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.ToString() + "." + System.Reflection.MethodBase.GetCurrentMethod().Name;
            ILog theLog = log4net.LogManager.GetLogger(strname);
            foreach (int prePort in m_arrPort)
            {
                if (!PortInUse(prePort))
                {
                    m_nPort = prePort;
#if DEBUG
                    Console.WriteLine("File info server will listen {0} UDP Port", prePort);
#endif
                    theLog.Info(string.Format("File info server will listen {0} UDP Port", prePort));
                    FlushBuffers();
                    break;
                }
            }
        }

        public void FlushBuffers()
        {
            log4net.Repository.ILoggerRepository rep = LogManager.GetRepository();
            foreach (log4net.Appender.IAppender appender in rep.GetAppenders())
            {
                var buffered = appender as log4net.Appender.BufferingAppenderSkeleton;
                if (buffered != null) buffered.Flush();
            }
        }

        public static bool PortInUse(int port)
        {
            bool inUse = false;
            IPGlobalProperties ipProperties = IPGlobalProperties.GetIPGlobalProperties();
            IPEndPoint[] ipEndPoints = ipProperties.GetActiveUdpListeners();
            foreach (IPEndPoint endPoint in ipEndPoints)
            {
                if (endPoint.Port == port)
                {
                    inUse = true;
                    break;
                }
            }
            return inUse;
        }

        public IOCPServer(int nPort)
        {
            m_nPort = nPort;
        }
        public void Start()
        {
            IPEndPoint localEndPoint = new IPEndPoint(IPAddress.Any, m_nPort);
            m_srvSocket = new Socket(AddressFamily.InterNetwork,
                SocketType.Dgram, ProtocolType.Udp);
            // Binding is required with ReceiveFrom calls.
            m_srvSocket.Bind(localEndPoint);
            ThreadPool.QueueUserWorkItem(ListenProc, this);
            for(int i=0;i<m_nWorkThreadNum;i++) ThreadPool.QueueUserWorkItem(TaskProc, null);
        }
        public void Stop()
        {
            m_bStop.Set();
            Thread.Sleep(500);
        }

        // Process request
        static void TaskProc(Object theTasks)
        {
            string strname = System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.ToString() + "." + System.Reflection.MethodBase.GetCurrentMethod().Name;
            ILog theLog = log4net.LogManager.GetLogger(strname);
            while (true)
            {
                WorkItem theItem = null;
                lock (m_objLock)
                {
                    if (m_theTasks.Count > 0)
                    {
                        theItem = m_theTasks[0];
                        m_theTasks.RemoveAt(0);
                    }
                }
                if (theItem != null)
                {
                    IPEndPoint endPoint = theItem.m_csocket as IPEndPoint;
                    try
                    {
                        byte[] bresp = RequestParser.ParseRequestPackage(theItem.m_szbuf, endPoint.Address.ToString());
                        int nSend = m_srvSocket.SendTo(bresp, theItem.m_csocket);
                        if (nSend != bresp.Length) theLog.Error(String.Format("Send data of [{0}] to {1}:{2} failed, length is not correct.",
                            System.Text.Encoding.UTF8.GetString(bresp,0,nSend), endPoint.Address, endPoint.Port));
                        else if (m_gDebug)  theLog.Debug(String.Format("Send data of [{0}] to {1}:{2} succeed.", System.Text.Encoding.UTF8.GetString(bresp,0,nSend),(theItem.m_csocket as IPEndPoint).Address,
                            (theItem.m_csocket as IPEndPoint).Port.ToString()));
                    }
                    catch (Exception exp)
                    {
                        theLog.Error(String.Format("Process data for {0}:{1} failed. ex is {2}", endPoint.Address, endPoint.Port, exp.ToString()));
                    }
                }
                if (m_bStop.WaitOne(100))
                {
                    if (m_gDebug) theLog.Info("Get stop signal , break from work thread at here.");
                    break;
                }
            }
        }
        static void ListenProc(Object theSocket)
        {
            if (m_srvSocket == null) return;
            byte[] msg = new Byte[m_nRecvBufLen];
            string strname = System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.ToString() + "." + System.Reflection.MethodBase.GetCurrentMethod().Name;
            ILog theLog = log4net.LogManager.GetLogger(strname);
            int nAVailable = 0;
            ArrayList listenList = new ArrayList();
            listenList.Add(m_srvSocket);
            while (true)
            {
                // waiting for stop signle
                if (m_bStop.WaitOne(10))
                {
                    m_srvSocket.Shutdown(SocketShutdown.Both);
                    m_srvSocket.Close();
                    if (m_gDebug) theLog.Info("Get stop signal , close socket at here.");
                    break;
                }

                nAVailable = m_srvSocket.Available;
                Socket.Select(listenList, null, null, 500);
                // timeout continue;
                if (listenList.Count == 0)
                {
                    listenList.Add(m_srvSocket);
                    continue;
                }

                if (nAVailable > 0)
                {
                    // Creates an IPEndPoint to capture the identity of the sending host.
                    EndPoint newClient = new IPEndPoint(IPAddress.Any, 0);
                    int nlen = 0;
                    try
                    {
                        nlen = m_srvSocket.ReceiveFrom(msg, msg.Length, SocketFlags.None, ref newClient);
                    }
                    catch(Exception exp)
                    {
                        theLog.Error(String.Format("Receive data from {0}:{1} failed, exp is : {2}", (newClient as IPEndPoint).Address.ToString(),
                                      (newClient as IPEndPoint).Port.ToString(), exp.ToString()));
                        nlen = 0;
                    }
                    if (nlen > 0)
                    {
                        WorkItem theItem = new WorkItem(nlen, msg, newClient);
                        lock (m_objLock) m_theTasks.Add(theItem);
                        if (m_gDebug && nAVailable > m_nRecvBufLen) theLog.Debug(String.Format("Receive data of [{0}],len is {1} from {2}:{3}. AVailable len is {4}.", 
                            System.Text.Encoding.UTF8.GetString(msg,0,nlen), nlen,(newClient as IPEndPoint).Address.ToString(),
                                                    (newClient as IPEndPoint).Port.ToString(), nAVailable));
                    }
                }
            }
        }
    }
}
