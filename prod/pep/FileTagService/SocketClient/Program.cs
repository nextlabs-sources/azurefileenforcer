using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Net;
using System.Runtime.Serialization;
using System.IO;
using SocketServer;
using System.Web.Script.Serialization;

namespace SocketClient
{
    class Program
    {
        public static string[] strArrHeader = { "NxlGetFileInfo  ", "NxlSetTimer     ", "NxlTimerResult  ", "NxlBadHeader    " };
        public static int HeaderLength = 16;
        public static int IntLength = 4;
        public const string m_strAccount = "storage188888";
        public const string m_strAuthorKey = "ci+cVvJpmWxrz1kDS5iCH5IEW6hwzNuhiGLURTX8qh6P+vEtAeSY/xsSFDvjcQafimEokel6/uAMvvCT0bBfSQ==";
        public static int m_nIntervalTime = 600;
        public static string[] m_lKeywords = { "Itar", "Deny", "Ip" };
        public static Socket m_clientSocket = null;
        public static object m_taskLock = new object();

        static void Main(string[] args)
        {
            const string REPL_MODE = "repl";
            const string PRESSURE_MODE = "pressure";
            const string CI_MODE = "ci";
            const string Timer_MODE = "setTimer";
            const string CheckTimer_MODE = "checkTimer";
            const string Quit_MODE = "quit";
            Console.WriteLine("Please input remote host ip address: ");
            string strIP = Console.ReadLine();           
            try
            {
                m_clientSocket = ConnectFileService(strIP);
                do
                {
                    Console.WriteLine("Please choose mode: 'SetTimer', 'checkTimer', 'repl', 'pressure', 'ci', 'quit'");
                    string strMode = Console.ReadLine();

                    try
                    {
                        if (strMode.Equals(REPL_MODE, StringComparison.CurrentCultureIgnoreCase))
                        {
                            REPL();
                        }
                        else if (strMode.Equals(PRESSURE_MODE, StringComparison.CurrentCultureIgnoreCase))
                        {
                            MultiThreadMock();
                        }
                        else if (strMode.Equals(CI_MODE, StringComparison.CurrentCultureIgnoreCase))
                        {
                            CITest();
                        }
                        else if (strMode.Equals(Timer_MODE, StringComparison.CurrentCultureIgnoreCase))
                        {
                            ProcessTimer();
                        }
                        else if (strMode.Equals(CheckTimer_MODE, StringComparison.CurrentCultureIgnoreCase))
                        {
                            CheckTimerStatus();
                        }
                        else if (strMode.Equals(Quit_MODE, StringComparison.CurrentCultureIgnoreCase))
                        {
                            break;
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message);
                    }

                } while (true);

            }
            catch (Exception exp)
            {
                Console.WriteLine("Main Exception:" + exp.Message);
            }
            finally
            {
                if (m_clientSocket != null)
                {
                    m_clientSocket.Close();
                }
            }
            Console.ReadLine();
        }
        public static byte[] ConstructBody(string strHeader, string strBodyData)
        {
            byte[] byteHeader = Encoding.UTF8.GetBytes(strHeader);
            byte[] byteLength = BitConverter.GetBytes(strBodyData.Length);
            byte[] byteResponse = Encoding.UTF8.GetBytes(strBodyData);
            byte[] lData = new byte[HeaderLength + IntLength + byteResponse.Length];
            if (byteHeader != null && byteHeader.Length == HeaderLength)
            {
                Array.Copy(byteHeader, 0, lData, 0, HeaderLength);
            }
            if (byteLength != null && byteLength.Length == IntLength)
            {
                Array.Copy(byteLength, 0, lData, HeaderLength, IntLength);
            }
            if (byteResponse != null && byteResponse.Length == byteResponse.Length)
            {
                Array.Copy(byteResponse, 0, lData, HeaderLength + IntLength, byteResponse.Length);
            }
            return lData;
        }

        public static byte[] CreateFileInfoRequest(string strRelativePath, string[] lKeywords)
        {
            FileInfoRequest fileReq = new FileInfoRequest();
            fileReq.RelativePath = strRelativePath;
            fileReq.Keywords = lKeywords;
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            string strBody = serializer.Serialize(fileReq);
            return ConstructBody(strArrHeader[0], strBody);
        }

        public static byte[] CreateTimerRequest(string strAccount, string strAuthorKey, string[] lKeywords, int intervalTime)
        {
            TimerSettingRequest timerReq = new TimerSettingRequest();
            timerReq.Account = strAccount;
            timerReq.AppAuthorKey = strAuthorKey;
            timerReq.Keywords = lKeywords;
            timerReq.IntervalTime = intervalTime;
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            string strBody = serializer.Serialize(timerReq);
            return ConstructBody(strArrHeader[1], strBody);
        }

        public static byte[] CreateCheckTimerRequest(string strAccount)
        {
            CheckTimerRequest timerCheckReq = new CheckTimerRequest();
            timerCheckReq.Account = strAccount;
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            string strBody = serializer.Serialize(timerCheckReq);
            return ConstructBody(strArrHeader[2], strBody);
        }

        public static Socket ConnectFileService(string strHost, int port = 6666)
        {
            string host = strHost;
            IPAddress ip = IPAddress.Parse(host);
            IPEndPoint ipe = new IPEndPoint(ip, port);
            Socket clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            clientSocket.Connect(ipe);
            return clientSocket;
        }
       
        private static void ProcessTimer()
        {
            if (m_clientSocket != null)
            {
                try
                {
                    Console.WriteLine("\ninput Timer keywords(separated by comma): ");
                    string strKeywords = Console.ReadLine();
                    if (!string.IsNullOrEmpty(strKeywords))
                    {
                        m_lKeywords = strKeywords.Split(',');
                    }

                    Console.WriteLine("\ninput : Timer IntervalTime");
                    string strIntervalTim = Console.ReadLine();
                    if (!string.IsNullOrEmpty(strIntervalTim))
                    {
                        m_nIntervalTime = int.Parse(strIntervalTim);
                    }
                    byte[] bodyData = CreateTimerRequest(m_strAccount, m_strAuthorKey, m_lKeywords, m_nIntervalTime);
                    m_clientSocket.Send(bodyData);
                    //receive message
                    string responseData = ReadBuffers();
                    Console.WriteLine("ProcessTimer responseData :\n" + responseData);
                }
                catch (Exception exp)
                {
                    Console.WriteLine("ProcessTimer Exception :" + exp);
                }
            }
        }
        private static void CheckTimerStatus()
        {
            if (m_clientSocket != null)
            {
                try
                {
                    byte[] bodyData = CreateCheckTimerRequest(m_strAccount);
                    m_clientSocket.Send(bodyData);
                    //receive message
                    string responseData = ReadBuffers();
                    Console.WriteLine("CheckTimerStatus responseData :\n" + responseData);
                }
                catch (Exception exp)
                {
                    Console.WriteLine("CheckTimerStatus Exception :" + exp);
                }
            }
        }

        private static void SendRequest(byte[] bodyData)
        {
            lock (m_taskLock)
            {
                if (m_clientSocket != null)
                {
                    m_clientSocket.Send(bodyData);
                }
            }
        }

        private static void REPL()
        {
            while (true)
            {
                Console.WriteLine("\ninput file relative path(separated by single backslash): eg. 'efs\\Folder05\\Security=low.docx'");
                string strFileRelativePath = Console.ReadLine();

                DateTime begin = DateTime.Now;
                if (String.Equals(strFileRelativePath, "quit", StringComparison.CurrentCultureIgnoreCase))
                {
                    break;
                }
                else
                {
                    try
                    {
                        // req
                        byte[] thedata = CreateFileInfoRequest(strFileRelativePath, m_lKeywords);
                        SendRequest(thedata);

                        //receive message
                        string responseData = ReadBuffers();
                        Console.WriteLine("REPL responseData :\n" + responseData);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("exception: {0}", ex.Message);
                    }
                }
                Console.WriteLine("-------REPL------Spent---" + (DateTime.Now - begin).TotalMilliseconds);
            }
        }

        private static void MultiThreadMock()
        {
            Console.WriteLine("\ninput file relative path(separated by single backslash): eg. 'efs\\Folder05\\Security=low.docx'");
            string strFileRelativePath = Console.ReadLine();

            Console.WriteLine("\ninput keywords(separated by comma): ");
            string[] lKeywords = Console.ReadLine().Split(',');
            if (lKeywords != null && lKeywords.Length > 0)
            {
                lock (m_taskLock)
                {
                    m_lKeywords = lKeywords;
                }
            }

            Console.WriteLine("\ninput threads Count: ");
            string strCount = Console.ReadLine();
            int threadCount = int.Parse(strCount);

            for (int i = 0; i < threadCount; i++)
            {
                RunTask(strFileRelativePath);
            }
        }

        private static void RunTask(string strFileRelativePath)
        {
            Task.Run(() =>
            {
                try
                {
                    // req
                    byte[] thedata = CreateFileInfoRequest(strFileRelativePath, m_lKeywords);
                    SendRequest(thedata);

                    //receive message
                    string responseData = ReadBuffers();
                    Console.WriteLine("REPL responseData :\n" + responseData);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("exception: {0}", ex.Message);
                }
            });
        }

        private static string ReadBuffers()
        {
            string responseData = "";
            List<byte> chunks = new List<byte>();
            if (m_clientSocket != null)
            {
                lock (m_taskLock)
                {
                    int nBufferSize = 1024;
                    byte[] recBytes = new byte[nBufferSize];
                    int nByteReceived = 0;
                    do
                    {
                        nByteReceived = m_clientSocket.Receive(recBytes, 0, nBufferSize, SocketFlags.None);

                        if (nByteReceived != 0)
                        {
                            chunks.AddRange(recBytes);
                        }
                    }
                    while (m_clientSocket.Available > 0);
                }
            }
            responseData = Encoding.UTF8.GetString(chunks.ToArray<byte>());
            return responseData;
        }

        private static void CITest()
        {
            try
            {
                System.Timers.Timer timer = new System.Timers.Timer(10000);
                timer.AutoReset = true;
                timer.Elapsed += (object state, System.Timers.ElapsedEventArgs e) =>
                {
                    try
                    {
                        string strFileRelativePath = @"qa-test/test files/denypage.docx";
                        // req
                        byte[] thedata = CreateFileInfoRequest(strFileRelativePath, m_lKeywords);
                        SendRequest(thedata);

                        //receive message
                        string responseData = ReadBuffers();
                    }
                    catch(Exception exp)
                    {
                        Console.WriteLine("threadId: {0}, exception: {1}", Task.CurrentId, exp.Message);
                    }
                    //Console.WriteLine("CITest responseData :\n" + responseData);
                };
                timer.Start();
            }
            catch (Exception ex)
            {
                Console.WriteLine("exception: {1}", ex.Message);
            }
        }
    }
}
