using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IFilterTextReader;
using System.IO;
using System.Threading;
using log4net;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace SocketServer
{
    public class AzureFile
    {
        //private static string[] SupportFileExtension = { ".txt", ".pdf", ".docx", ".pptx", ".xlsx",
        //                        ".doc", ".docm", ".dot", ".dotx",
        //                        ".xlam", ".xls", ".xlsb", ".xlsm", ".xlt", ".xla",
        //                        ".pot", ".ppt", ".pptm", ".pps", ".ppam", ".ppa" };
        private static string[] SupportFileExtension = { ".txt", ".pdf", ".docx", ".pptx", ".xlsx",
                                ".docm", ".dotx", ".xlam", ".xlsb", ".xlsm", ".pptm", ".ppam" };
        //                        ".txt",
        //                        ".pdf",
        //                        ".docx", ".pptx", ".xlsx", //office 2007
        //                        ".docm", ".dotx", ".pptm", ".xlsb", ".xlsm", //office 2007
        //                        ".xlam",   // office 2007
        //                        ".ppam",   // office 2007
        //                        ".doc", ".dot", ".ppt", ".pps", ".pot", ".xls", ".xlt",   //office 2003
        //                        ".xla",   //office 2003
        //                        ".ppa"   // office 2003
        private ICache<string, NxlFileInfo> m_dicFileCache = new ConcurrentCache<string, NxlFileInfo>();
        private bool m_bKeywdEnable = false;    //if true, m_lKeywords is valid
        private string[] m_lKeywords = new string[0];
        private string[] m_lSharedFolders = new string[0];
        private int m_IntervalTime = 3600; // Timer Interval time(second).
        private readonly object m_objLock = new object();
        private string m_FSHost = "";

        // Task And Timer
        private ICache<string, NxlFileInfo> m_dicTimerFileCache = new ConcurrentCache<string, NxlFileInfo>();
        private DateTime m_timerBegin = DateTime.Now;
        private bool m_bTimerProcess = false;
        private bool m_bSetTimerEnd = false;
        private List<string> m_timerFileUrls = new List<string>();

        // it will used to enum all files and check file info
        // it will be used to replace cache directly only after finish scan
        private List<string> m_temptimerFileUrls = new List<string>();

        // undeleted file, start a thread to remove it
        private static readonly object m_delLock = new object();
        private static ConcurrentQueue<string> m_unDeletedFileUrls = new ConcurrentQueue<string>();
        private static bool m_bDelThread = false;

        // for processing request that the File information has not cached
        private readonly object m_WaitLock = new object();
        private ConcurrentQueue<string> m_WaitingFileUrls = new ConcurrentQueue<string>();
        private bool m_bWaitThread = false;

        private int m_fileUrlsIndex = 0;
        private const int m_maxTasks = 3;
        private System.Timers.Timer m_timer = null;

        private readonly object m_taskLock = new object();

        //private static readonly string[] Office2003Extensions = { ".doc", ".dot", ".ppt", ".pps", ".pot", ".xls", ".xlt", ".xla", ".ppa" };
        //private static readonly string[] IgnorePropertyExtensions = { ".txt", ".doc", ".dot", ".ppt", ".pps", ".pot", ".xls", ".xlt", ".xla", ".ppa" };
        //private static string[] NoOffice2003Extension = { ".txt", ".pdf", ".docx", ".pptx", ".xlsx", ".docm", ".dotx", ".xlam", ".xlsb", ".xlsm", ".pptm", ".ppam" };

        public AzureFile() { }

        // Return value: false means don't need change anything for timer.
        public bool CheckAndSetAzureTimerInfo(string strFSHost, string[] lKeywords, string[] lSharedFolders, int intervalTime)
        {
            if (lSharedFolders.Length != 0)
            {
                bool btempFlag;
                if (lKeywords.Length == 0) btempFlag = false;
                else btempFlag = true;
                lock (m_taskLock)
                {
                    if (btempFlag.Equals(m_bKeywdEnable) && (!btempFlag || IsValid(m_lKeywords, lKeywords)) &&
                        m_FSHost.Equals(strFSHost, StringComparison.OrdinalIgnoreCase) &&
                        m_IntervalTime == intervalTime &&
                        IsValid(m_lSharedFolders, lSharedFolders))
                        return false;
                    else
                    {
                        m_FSHost = strFSHost;
                        m_lKeywords = lKeywords;
                        m_bKeywdEnable = btempFlag;
                        m_lSharedFolders = lSharedFolders;
                        m_IntervalTime = intervalTime;
                        m_bSetTimerEnd = false; // Setting Timer Flag.
                        return true;
                    }
                }
            }
            else return false;
        }

        public void GetAzureTimerStatus(ref ResponseStatus status, ref string strMessage)
        {
            bool btempEnd = true;
            lock (m_taskLock) { btempEnd = m_bSetTimerEnd; }
            if (btempEnd)
            {
                status = ResponseStatus.Success;
                strMessage = "Finished process timer to get files information.";
            }
            else
            {
                status = ResponseStatus.Working;
                strMessage = "Timer is working on to get files information.";
            }
        }

        // enum all files and ask TimerWrapper read info again
        public void ProcessFileInfoTimer(ref ResponseStatus status, ref string strMessage)
        {
            string strname = System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.ToString() + "." + System.Reflection.MethodBase.GetCurrentMethod().Name;
            ILog theLog = log4net.LogManager.GetLogger(strname);
            status = ResponseStatus.Failed;
            strMessage = "Failed to process timer to get files information";
            try
            {
                bool bTask = false;
                lock (m_taskLock)
                {
                    //multi thread to update file info to cache, only update index to restart from 0
                    if (m_bTimerProcess) { m_fileUrlsIndex = 0; }
                    else
                    {
                        m_bTimerProcess = true;
                        if (m_timer != null) m_timer.Stop();
                        // Init before Timer.
                        m_timerBegin = DateTime.Now;
                        m_timerFileUrls.Clear(); // clear Urls before.
                        m_fileUrlsIndex = 0;
                        bTask = true;
                    }
                }
                if (bTask) { Task.Run(new Action(TimerWrapper)); }
                status = ResponseStatus.Working;
                strMessage = "Timer is working on to get files information.";
            }
            catch (Exception exp)
            {
                theLog.Equals("ProcessFileInfoTimer Exception: " + exp.ToString());
                status = ResponseStatus.Failed;
                strMessage = exp.Message;
            }
        }

        // Get Domain File Info based on SMB server request
        public bool GetFileInfo(string strFSHost, string strFileRelativePath, string[] lKeywords, ref Dictionary<string, int> dicKeywordsCount,
                                ref Dictionary<string, string> dicProperties, ref ResponseStatus status, ref string strMessage)
        {
            string strname = System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.ToString() + "." + System.Reflection.MethodBase.GetCurrentMethod().Name;
            ILog theLog = log4net.LogManager.GetLogger(strname);
            status = ResponseStatus.Failed;
            strMessage = "Failed to read file information for path: " + strFileRelativePath;
            try
            {
                if (String.IsNullOrEmpty(strFSHost) || string.IsNullOrWhiteSpace(strFSHost))
                {
                    status = ResponseStatus.InvalidPath;
                    strMessage = "The file host is empty.";
                    return false;
                }
                if (String.IsNullOrEmpty(strFileRelativePath) || string.IsNullOrWhiteSpace(strFileRelativePath))
                {
                    status = ResponseStatus.InvalidPath;
                    strMessage = "The file path is empty.";
                    return false;
                }
                if (!CheckSupportExtension(strFileRelativePath))
                {
                    status = ResponseStatus.UnSupportExt;
                    strMessage = string.Format("File Info Server don't support {0} type.", strFileRelativePath.Substring(strFileRelativePath.LastIndexOf('.')));
                    return false;
                }
                string strFileUrl = String.Format("\\\\{0}\\{1}", strFSHost, strFileRelativePath);
                if (!File.Exists(strFileUrl))
                {
                    theLog.Info(string.Format("{0} don't existed.", strFileUrl));
                    status = ResponseStatus.OutOfDate;
                    strMessage = "The file don't existed.";
                    return false;
                }
                else if (new FileInfo(strFileUrl).Length == 0)
                {
                    theLog.Info(string.Format("{0} is empty file and isn't cached.", strFileUrl));
                    status = ResponseStatus.EmptyFile;
                    strMessage = "The file is empty.";
                    return false;
                }
                NxlFileInfo fileInfo = null;
                bool bInCache = m_dicFileCache.TryGet(strFileUrl.ToLower(), ref fileInfo);
                bool bMod = false;
                if (bInCache) bMod = new FileInfo(strFileUrl).LastWriteTime.ToString() != fileInfo.FileLastModified;
                if (bInCache && !bMod)
                {
                    //if (theLog.IsDebugEnabled) theLog.Debug("properties of " + strFileUrl + " : ");
                    //string strtmplog = "";
                    if (fileInfo.ReadSuccess)
                    {
                        if (m_bKeywdEnable)
                        {
                            if (IsValid(fileInfo.KeywordsCount.Keys.ToArray<string>(), lKeywords))
                            {
                                dicKeywordsCount = fileInfo.KeywordsCount;
                                //if (theLog.IsDebugEnabled)
                                //{
                                //    strtmplog += "Keywords Count : \n";
                                //    foreach (var k in dicKeywordsCount.Keys) { strtmplog += k + " : " + dicKeywordsCount[k] + "\n"; }
                                //}
                                dicProperties = fileInfo.Properties;
                                //if (theLog.IsDebugEnabled)
                                //{
                                //    strtmplog += "Properties : \n";
                                //    foreach (var k in dicProperties.Keys) { strtmplog += k + " : " + dicProperties[k] + "\n"; }
                                //    theLog.Debug(strtmplog.TrimEnd('\n'));
                                //}
                                status = ResponseStatus.Success;
                                strMessage = string.Format("Success to get file information of {0}", strFileUrl);
                                return true;
                            }
                            else
                            {
                                lock (m_objLock)
                                {
                                    if (lKeywords.Length == 0) m_bKeywdEnable = false;
                                    else m_bKeywdEnable = true;
                                    m_lKeywords = lKeywords;    // Update KeyWords
                                } 
                                theLog.Info("Update KeyWords : " + string.Join(",", m_lKeywords));
                            }
                        }
                        else
                        {
                            dicProperties = fileInfo.Properties;
                            //if (theLog.IsDebugEnabled)
                            //{
                            //    strtmplog += "Properties : \n";
                            //    foreach (var k in dicProperties.Keys) { strtmplog += k + " : " + dicProperties[k] + "\n"; }
                            //    theLog.Debug(strtmplog.TrimEnd('\n'));
                            //}
                            status = ResponseStatus.Success;
                            strMessage = string.Format("Success to get file information of {0}", strFileUrl);
                            return true;
                        }
                    }
                    else
                    {
                        theLog.Info(string.Format("{0} is in unreadable info status.", strFileUrl));
                        status = ResponseStatus.UnreadableInfo;
                        strMessage = string.Format("{0} is in a state of unreadable info.", strFileUrl);
                        return false;
                    }
                }
                else if(bMod) theLog.Info(string.Format("Cached info of {0} is out-of-date. Try to download file and read info.", strFileUrl.ToLower()));
                else theLog.Info(string.Format("File info server has not cached info of {0}. Try to download file and read info.", strFileUrl.ToLower()));
                lock (m_WaitLock)
                {
                    if (!m_WaitingFileUrls.Contains(strFileUrl)) m_WaitingFileUrls.Enqueue(strFileUrl);
                    if (theLog.IsDebugEnabled) theLog.Debug(string.Format("Enqueue {0}, Now WaitingFileUrls Count is {1}, bWaitThread is {2}.", strFileUrl, m_WaitingFileUrls.Count, m_bWaitThread));
                    if (!m_bWaitThread)
                    {
                        m_bWaitThread = true;
                        ThreadPool.QueueUserWorkItem(CacheWaitingFile);
                    }
                }
                status = ResponseStatus.TimeOut;
                strMessage = "Time out, new one task to read file information.";
            }
            catch (Exception exp)
            {
                theLog.Error(String.Format("GetFileInfo of \\\\{0}\\{1} failed , Exception {2}.", strFSHost, strFileRelativePath, exp.ToString()));
                strMessage = exp.Message;
            }
            return false;
        }

        private void CacheWaitingFile(object status)
        {
            string strname = System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.ToString() + "." + System.Reflection.MethodBase.GetCurrentMethod().Name;
            ILog theLog = log4net.LogManager.GetLogger(strname);
            //Thread.CurrentThread.Priority = ThreadPriority./*Highest*/Normal;
            //if(theLog.IsDebugEnabled) theLog.Debug($"Thread priority : {Thread.CurrentThread.Priority}.");
            while (true)
            {
                string curUrl;
                if (!m_WaitingFileUrls.TryDequeue(out curUrl)) break;
                if (theLog.IsDebugEnabled) theLog.Debug(string.Format("TryDequeue {0}, now WaitingFileUrls Count is {1}, bWaitThread is {2}.", curUrl, m_WaitingFileUrls.Count, m_bWaitThread));
                if (!string.IsNullOrEmpty(curUrl) && File.Exists(curUrl))
                {
                    if (m_dicFileCache.Keys.Contains(curUrl.ToLower())) continue;
                    string strTempFile = string.Empty, strDestFile = string.Empty;
                    try
                    {
                        string strFolder = string.Empty;
                        GetFolder(curUrl, ref strFolder);
                        if (!m_lSharedFolders.Contains(strFolder))
                        {
                            theLog.Info(string.Format("{0} isn't included in shared folder list from smbProxy", curUrl));
                            continue;
                        }
                        if (!File.Exists(curUrl))
                        {
                            theLog.Info(string.Format("{0} hasn't existed anymore.", curUrl));
                            continue;
                        }
                        else if (new FileInfo(curUrl).Length == 0)
                        {
                            theLog.Info(string.Format("File info server will not cache empty file : {0}", curUrl));
                            continue;
                        }
                        Dictionary<string, int> dicKeywordsCount = new Dictionary<string, int>();
                        Dictionary<string, string> dicProps = new Dictionary<string, string>();
                        NxlFileInfo fileInfoTobeCached = new NxlFileInfo();
                        if (m_bKeywdEnable) initKeyCounts(dicKeywordsCount, m_lKeywords);
                        strTempFile = Path.GetTempFileName();
                        SafelyDeleteFile(strTempFile);
                        string fileExtension = Path.GetExtension(curUrl);
                        strDestFile = strTempFile + fileExtension;
                        File.Copy(curUrl, strDestFile, true);
                        bool bExpReadInfo = false;
                        bool bIsInfoRead = ReadInfo(strDestFile, curUrl, fileExtension, dicKeywordsCount, ref dicProps, m_lKeywords, ref bExpReadInfo);
                        if (!bExpReadInfo)
                        {
                            if (bIsInfoRead || dicProps.Count != 0)
                            {
                                theLog.Info("Read success : " + curUrl + ", temp : " + strDestFile);
                                fileInfoTobeCached.ReadSuccess = true;
                                fileInfoTobeCached.Properties = dicProps;
                                fileInfoTobeCached.FileLastModified = new FileInfo(strDestFile).LastWriteTime.ToString();
                                if (m_bKeywdEnable) fileInfoTobeCached.KeywordsCount = dicKeywordsCount; // Set Keywords
                                m_dicFileCache.Set(curUrl.ToLower(), fileInfoTobeCached);
                            }
                            else
                            {
                                fileInfoTobeCached.ReadSuccess = false;
                                fileInfoTobeCached.FileLastModified = new FileInfo(strDestFile).LastWriteTime.ToString();
                                theLog.Info(string.Format("{0} will cached, but don't Cache any property.", curUrl));
                                m_dicFileCache.Set(curUrl.ToLower(), fileInfoTobeCached);
                            }
                        }
                    }
                    catch (Exception exp) { theLog.Error("CacheWaitingFile " + curUrl + " failed, Exception is: " + exp.ToString()); }
                    finally
                    {
                        SafelyDeleteFile(strDestFile);
                    }
                }
                Thread.Sleep(100);
            }
            lock (m_WaitLock) { m_bWaitThread = false; }
        }

        //when using for Action or lambda, Exception cannot throw out, so need a try-cache
        private void TimerWrapper()
        {
            string strname = System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.ToString() + "." + System.Reflection.MethodBase.GetCurrentMethod().Name;
            ILog theLog = log4net.LogManager.GetLogger(strname);
            try
            {
                EnumAllDicFiles();
                lock (m_taskLock) { m_timerFileUrls = m_temptimerFileUrls; } // set Urls and lock one time only.
                m_temptimerFileUrls = new List<string>();
                //delete out-of-date file info of timer cache
                List<string> lTimerCachedFiles = m_dicTimerFileCache.Keys;
                foreach (string fi in lTimerCachedFiles.Except(m_timerFileUrls))
                {
                    theLog.Info(string.Format("Deleting out-of-date URL : {0}", fi));
                    m_dicTimerFileCache.Delete(fi);
                }
                for (int i = 0; i<m_maxTasks; i++) Task.Run(new Action(TaskReadFile));
            }
            catch (Exception exp) { theLog.Error(exp.ToString()); }
        }

        private void TaskReadFile()
        {
            string strname = System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.ToString() + "." + System.Reflection.MethodBase.GetCurrentMethod().Name;
            ILog theLog = log4net.LogManager.GetLogger(strname);
            Thread.CurrentThread.Priority = ThreadPriority.Lowest;
            if (theLog.IsDebugEnabled) theLog.Debug($"Thread priority : {Thread.CurrentThread.Priority}.");
            try
            {
                do
                {
                    String fileUrl = string.Empty;
                    lock (m_taskLock)
                    {
                        if (m_fileUrlsIndex < m_timerFileUrls.Count) { fileUrl = m_timerFileUrls[m_fileUrlsIndex++]; }
                        else if (m_fileUrlsIndex == m_timerFileUrls.Count)
                        {
                            m_fileUrlsIndex++;
                            m_dicFileCache.Update((ConcurrentCache<string, NxlFileInfo>)m_dicTimerFileCache);
                            //long ll = GetObjectSize(m_dicFileCache) - GetObjectSize(new ConcurrentCache<string, NxlFileInfo>());
                            if (m_timer == null)
                            {
                                m_timer = new System.Timers.Timer(m_IntervalTime * 1000); // Convert time from second to millisecond.
                                m_timer.Elapsed += new System.Timers.ElapsedEventHandler(TimerProcess);
                                m_timer.AutoReset = false;
                            }
                            if (!m_timer.Enabled)
                            {
                                m_timer.Interval = m_IntervalTime * 1000;
                                m_bSetTimerEnd = true;
                                DateTime timerEnd = DateTime.Now;
                                theLog.Info(string.Format("Traversal timer for {0} start at {1}, end at {2}, total cost : {3}", m_FSHost, m_timerBegin, timerEnd, (timerEnd - m_timerBegin).ToString()));
                                m_bTimerProcess = false;
                                m_timer.Start();
                            }
                            break;
                        }
                        else break;
                    }
                    if ((!string.IsNullOrEmpty(fileUrl)) && File.Exists(fileUrl)) TimerReadFileInfo(fileUrl);
                } while (true);
            }
            catch (Exception e)
            {
                theLog.Error(e.ToString());
            }
        }

        // Process all files in the directory passed in, recurse on any directories 
        // that are found, and process the files they contain.
        private void ProcessDirectory(string targetDirectory)
        {
            // Process the list of files found in the directory.
            string[] fileEntries = Directory.GetFiles(targetDirectory);
            foreach (string fileName in fileEntries) { ProcessFile(fileName); }

            // Recurse into subdirectories of this directory.
            string[] subdirectoryEntries = Directory.GetDirectories(targetDirectory);
            foreach (string subdirectory in subdirectoryEntries) { ProcessDirectory(subdirectory); }
        }

        private void ProcessFile(string path)
        {
            if (!CheckSupportExtension(path)) return;
            if (!m_temptimerFileUrls.Contains(path.ToLower()))  { m_temptimerFileUrls.Add(path.ToLower());}
        }

        //Enum Domain Folders Files
        private void EnumAllDicFiles()
        {
            string strname = System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.ToString() + "." + System.Reflection.MethodBase.GetCurrentMethod().Name;
            ILog theLog = log4net.LogManager.GetLogger(strname);
            theLog.Info("Start traversal timer for " + m_FSHost);
            //enum all files by UNC path
            foreach (string strFolder in m_lSharedFolders)
            {
                string SharedFolderPath = String.Format("\\\\{0}\\{1}\\", m_FSHost, strFolder);
                if (Directory.Exists(SharedFolderPath)) { ProcessDirectory(SharedFolderPath); }
            }
        }

        public void TimerProcess(object source, System.Timers.ElapsedEventArgs e)
        {
            ResponseStatus status = ResponseStatus.Failed;
            string strMessage = "";
            ProcessFileInfoTimer(ref status, ref strMessage);
        }

        //when using for Action or lambda, Exception cannot throw out, so need a try-cache
        private void TimerReadFileInfo(string strFileUrl)
        {
            if (strFileUrl != null)
            {
                NxlFileInfo fileInfo = null;
                fileInfo = m_dicTimerFileCache.Get(strFileUrl.ToLower());
                if (fileInfo != null)
                {
                    string fileLastModified = new FileInfo(strFileUrl).LastWriteTime.ToString();
                    if (m_bKeywdEnable)
                    {
                        bool bIsValid = IsValid(fileInfo.KeywordsCount.Keys.ToArray<string>(), m_lKeywords);
                        if (fileLastModified == fileInfo.FileLastModified && bIsValid) return;
                    }
                    else if (fileLastModified == fileInfo.FileLastModified) return;
                }
                TimerDownloadFileAndReadInfo(strFileUrl, m_lKeywords);
            }
        }

        private static void RemoveTempFile(object status = null)
        {
            string strname = System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.ToString() + "." + System.Reflection.MethodBase.GetCurrentMethod().Name;
            ILog theLog = log4net.LogManager.GetLogger(strname);
            Thread.CurrentThread.Priority = ThreadPriority.Lowest;
            if (theLog.IsDebugEnabled) theLog.Debug($"Thread priority : {Thread.CurrentThread.Priority}.");
            while (true)
            {
                string curUrl;
                if (!m_unDeletedFileUrls.TryDequeue(out curUrl)) break;
                if (theLog.IsDebugEnabled) theLog.Debug(string.Format("Try to delete {0}.", curUrl));
                if (!string.IsNullOrEmpty(curUrl) && File.Exists(curUrl))
                {
                    try
                    {
                        File.SetAttributes(curUrl, FileAttributes.Normal);
                        File.Delete(curUrl);
                    }
                    catch
                    {
                        if (!m_unDeletedFileUrls.Contains(curUrl))
                        {
                            if (theLog.IsDebugEnabled) theLog.Debug(string.Format("Re-Enqueue {0}.", curUrl));
                            m_unDeletedFileUrls.Enqueue(curUrl);
                        }
                    }
                }
                Thread.Sleep(500);
            }
            lock (m_delLock) { m_bDelThread = false; }
        }

        private static void SafelyDeleteFile(string strfi)
        {
            string strname = System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.ToString() + "." + System.Reflection.MethodBase.GetCurrentMethod().Name;
            ILog theLog = log4net.LogManager.GetLogger(strname);
            try
            {
                if (!string.IsNullOrEmpty(strfi) && File.Exists(strfi))
                {
                    //https://stackoverflow.com/questions/8821410/why-is-access-to-the-path-denied
                    File.SetAttributes(strfi, FileAttributes.Normal);
                    File.Delete(strfi);
                }
            }
            catch (Exception e)
            {
                lock (m_delLock)
                {
                    if (!m_unDeletedFileUrls.Contains(strfi)) m_unDeletedFileUrls.Enqueue(strfi);
                    if (!m_bDelThread)
                    {
                        m_bDelThread = true;
                        ThreadPool.QueueUserWorkItem(RemoveTempFile);
                    }
                }
                theLog.Info(string.Format("[Ignore]{0} File info server will delete it later.", e.Message));
            }
        }

        //when using for Action or lambda, Exception cannot throw out, so need a try-cache
        private void TimerDownloadFileAndReadInfo(string strFileUrl, string[] lKeywords)
        {
            string strname = System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.ToString() + "." + System.Reflection.MethodBase.GetCurrentMethod().Name;
            ILog theLog = log4net.LogManager.GetLogger(strname);
            string strTempFile = string.Empty, strDestFile = string.Empty;
            try
            {
                if (!File.Exists(strFileUrl))
                {
                    theLog.Info(string.Format("{0} hasn't existed anymore.", strFileUrl));
                    return;
                }
                else if (new FileInfo(strFileUrl).Length == 0)
                {
                    theLog.Info("File info server will not cache null file : " + strFileUrl);
                    return;
                }
                Dictionary<string, int> dicKeywordsCount = new Dictionary<string, int>();
                Dictionary<string, string> dicProps = new Dictionary<string, string>();
                NxlFileInfo fileInfoTobeCached = new NxlFileInfo();
                if(m_bKeywdEnable) initKeyCounts(dicKeywordsCount, lKeywords);
                strTempFile = Path.GetTempFileName();
                string fileExtension = Path.GetExtension(strFileUrl);
                strDestFile = strTempFile + fileExtension;
                File.Copy(strFileUrl, strDestFile, true);
                bool bExpReadInfo = false;
                bool bIsInfoRead = ReadInfo(strDestFile, strFileUrl, fileExtension, dicKeywordsCount, ref dicProps, lKeywords, ref bExpReadInfo);
                if (!bExpReadInfo)
                {
                    if (bIsInfoRead || dicProps.Count != 0)
                    {
                        theLog.Info("Read success : " + strFileUrl + ", temp : " + strDestFile);
                        fileInfoTobeCached.ReadSuccess = true;
                        fileInfoTobeCached.Properties = dicProps;
                        fileInfoTobeCached.FileLastModified = new FileInfo(strDestFile).LastWriteTime.ToString();
                        if (m_bKeywdEnable) fileInfoTobeCached.KeywordsCount = dicKeywordsCount; // Set Keywords
                        m_dicTimerFileCache.Set(strFileUrl.ToLower(), fileInfoTobeCached);
                    }
                    else
                    {
                        fileInfoTobeCached.ReadSuccess = false;
                        fileInfoTobeCached.FileLastModified = new FileInfo(strDestFile).LastWriteTime.ToString();
                        theLog.Info(string.Format("{0} will cached, but 'bReadSuccess' Status is set as 'false'.", strFileUrl.ToLower()));
                        m_dicTimerFileCache.Set(strFileUrl.ToLower(), fileInfoTobeCached);
                    }
                }
            }
            catch (Exception exp) { theLog.Error("TimerDownloadFileAndReadInfo from " + strFileUrl + " failed, Exception is: " + exp.ToString()); }
            finally
            {
                SafelyDeleteFile(strTempFile);
                SafelyDeleteFile(strDestFile);
            }
        }

        private bool ReadInfo(string strFilePath, string strOrgPath, string strExtension, Dictionary<string, int> dicKeywordsCount, ref Dictionary<string, string> dicProperties, string[] lKeywords, ref bool bExpFlag)
        {
            bool bReadInfo = false;
            string strname = System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.ToString() + "." + System.Reflection.MethodBase.GetCurrentMethod().Name;
            ILog theLog = log4net.LogManager.GetLogger(strname);
            //string strtmplog = "";
            try
            {
                if (!string.IsNullOrEmpty(strFilePath))
                {
                    using (var reader = new FilterReader(strFilePath, strExtension, false, true))
                    {
                        string fileText = null;
                        if (strFilePath.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))fileText = reader.ReadToEnd();
                        else fileText = reader.ReadToEndWithProperties(dicProperties);
                        if (m_bKeywdEnable)
                        {
                            if (!string.IsNullOrEmpty(fileText))
                            {
                                foreach (var key in lKeywords)
                                {
                                    string pattern = @"\b" + key + @"\b";
                                    System.Text.RegularExpressions.Regex regex = new System.Text.RegularExpressions.Regex(pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                                    System.Text.RegularExpressions.MatchCollection matches = regex.Matches(fileText);

                                    if (matches.Count > 0) { dicKeywordsCount[key] = matches.Count; }
                                }
                                bReadInfo = true;
                            }
                            else if (dicProperties.Count != 0) bReadInfo = true;
                        }
                        else if (strFilePath.TrimEnd().ToLower().EndsWith(".txt")) return true; //txt has no property
                        else if (dicProperties.Count != 0) bReadInfo = true;
                        //if (theLog.IsDebugEnabled)
                        //{
                        //    if (m_bKeywdEnable)
                        //    {
                        //        strtmplog += "Keywords Count : \n";
                        //        foreach (var k in dicKeywordsCount.Keys) { strtmplog += k + " : " + dicKeywordsCount[k] + "\n"; }
                        //    }
                        //    strtmplog += "Properties : \n";
                        //    foreach (var k in dicProperties.Keys) { strtmplog += k + " : " + dicProperties[k] + "\n"; }
                        //}
                    }
                }
            }
            catch (IFilterTextReader.Exceptions.IFOldFilterFormat)
            {
                bExpFlag = true;
                //Corrupted files exceptions will be ignored.
                theLog.Info(string.Format("[Ignore]Failed to read info of file : {0}, maybe the file is encrypted, corrupted or its file format does not match extension name.", strOrgPath));
            }
            catch (Exception exp)
            {
                bExpFlag = true;
                theLog.Error("ReadInfo from file of: " + strOrgPath + " failed, Exception is: " + exp.ToString());
            }
            if (theLog.IsDebugEnabled) theLog.Debug("FilePath : " + strFilePath + ", OrgPath : " + strOrgPath + ", bReadInfo : " + bReadInfo + ", Properties Count : " + dicProperties.Count);

            return bReadInfo;
        }

        private void initKeyCounts(Dictionary<string, int> dicKeywordCounts, string[] keywords)
        {
            foreach (string keyword in keywords) { if (!String.IsNullOrEmpty(keyword)) dicKeywordCounts[keyword] = 0; }
        }

        private static bool IsValid(string[] lCachedKeywords, string[] lNewKeywords)
        {
            if(lCachedKeywords.Length != lNewKeywords.Length) return false;
            return lNewKeywords.All((keyword) => lCachedKeywords.Contains(keyword));
        }

        private static bool CheckSupportExtension(string fileUrl)
        {
            foreach (string strExtension in SupportFileExtension) { if (fileUrl.EndsWith(strExtension, StringComparison.OrdinalIgnoreCase)) return true; }
            return false;
        }

        public static void GetFolder(string path, ref string opath)
        {
            if (path.StartsWith("\\\\"))
            {
                int s = 0, e = 0, len = path.Length;
                bool bs = true, be = true;
                for (int i = 0; i < len; ++i)
                {
                    bool btemp = path[i].Equals('\\');
                    if (bs)
                    {
                        if (btemp) ++s;
                        if (s == 3) { bs = false; s = i + 1; }
                    }
                    if (be)
                    {
                        if (btemp) ++e;
                        if (e == 4) { be = false; e = i; }
                    }
                    if (!be && !bs) break;
                }
                opath = path.Substring(s, e - s);
            }
        }
    }
}
