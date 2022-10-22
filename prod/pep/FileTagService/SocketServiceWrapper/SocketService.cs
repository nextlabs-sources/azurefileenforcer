using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using SocketServer;
using System.IO;
using log4net;

namespace SocketServiceWrapper
{
    public partial class SocketService : ServiceBase
    {
        private IOCPServer m_strServer = null;
        public SocketService()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            string strname = System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.ToString() + "." + System.Reflection.MethodBase.GetCurrentMethod().Name;
            ILog theLog = log4net.LogManager.GetLogger(strname);
            Task.Run(() =>
            {
                //m_strServer = new IOCPServer(6666);
                m_strServer = new IOCPServer();
                m_strServer.Start();
                theLog.Info(String.Format("Socket service started at {0}.", DateTime.Now.ToShortTimeString()));
            });
        }

        protected override void OnStop()
        {
            string strname = System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.ToString() + "." + System.Reflection.MethodBase.GetCurrentMethod().Name;
            ILog theLog = log4net.LogManager.GetLogger(strname);
            if (m_strServer != null)
            {
                m_strServer.Stop();
                theLog.Info(String.Format("Socket service stopped at {0}.", DateTime.Now.ToShortTimeString()));
            }
        }
    }
}
