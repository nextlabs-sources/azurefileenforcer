using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.Serialization;
using System.Web.Script.Serialization;
using log4net;

namespace SocketServer
{
    [DataContract]
    public class NxlFileInfo
    {
        [DataMember]
        public string FileLastModified { get; set; }   // Last modified time on azure file

        [DataMember]
        public Dictionary<string, int> KeywordsCount { get; set; }

        [DataMember]
        public Dictionary<string, string> Properties { get; set; }

        [DataMember]
        public bool ReadSuccess { get; set; }

        public NxlFileInfo()
        {
            KeywordsCount = new Dictionary<string, int>();
            Properties = new Dictionary<string, string>();
            ReadSuccess = false;
        }
    }

    [DataContract]
    public class FileInfoRequest
    {
        [DataMember]
        public string FSHost { get; set; }

        [DataMember]
        public string FSAccount { get; set; }

        [DataMember]
        public string FSPassword { get; set; }

        [DataMember]
        public string RelativePath { get; set; }

        [DataMember]
        public string[] Keywords { get; set; }
    }

    [DataContract]
    public class TimerSettingRequest
    {
        [DataMember]
        public string FSHost { get; set; }

        [DataMember]
        public string Account { get; set; }

        [DataMember]
        public string AppAuthorKey { get; set; }

        [DataMember]
        public string[] Keywords { get; set; }

        [DataMember]
        public string[] SharedFolders { get; set; }

        [DataMember]
        public int IntervalTime { get; set; } // Timer Interval time(second).
    }

    [DataContract]
    public class CheckTimerRequest
    {
        [DataMember]
        public string FSHost { get; set; }

        [DataMember]
        public string Account { get; set; }
    }

    [DataContract]
    public class FileInfoResponse
    {
        [DataMember]
        public string Status { get; set; }

        [DataMember]
        public string Message { get; set; }

        [DataMember]
        public string RelativePath { get; set; }

        [DataMember]
        public Dictionary<string, int> Keywords { get; set; }

        [DataMember]
        public Dictionary<string, string> Properties { get; set; }
    }

    [DataContract]
    public class StatusResponse
    {
        [DataMember]
        public string Status { get; set; }

        [DataMember]
        public string Message { get; set; }

        public StatusResponse(string inputStatus, string inputMessage)
        {
            Status = inputStatus;
            Message = inputMessage;
        }
    }

    public enum ResponseStatus
    {
        Success,
        Failed,
        Working,
        EmptyFile,
        OutOfDate,
        TimeOut,
        InvalidPath,
        UnreadableInfo,
        BadRequest,
        UnSupportExt,
    }

    [DataContract]
    public class HeartBeatResponse
    {
        [DataMember]
        public string Status { get; set; }

        public HeartBeatResponse(HeartBeatStatus status)
        {
            Status = status.ToString();
        }
    }

    public enum HeartBeatStatus
    {
        Cached,
        NotCached
    }

    public class RequestParser
    {
        public static string[] strArrHeader = { "NxlGetFileInfo  ", "NxlSetTimer     ", "NxlTimerResult  ", "NxlHeartBeat    ", "NxlBadHeader    " };
        public static int HeaderLength = 16;
        public static int IntLength = 4;
        private static List<string> m_ParseredProxy = new List<string>(); 
        private static Dictionary<string, AzureFile> dicAzureFiles = new Dictionary<string, AzureFile>();
        public static byte[] ParseRequestPackage(byte[] byteData, string smbproxy)
        {
            string strname = System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.ToString() + "." + System.Reflection.MethodBase.GetCurrentMethod().Name;
            ILog theLog = log4net.LogManager.GetLogger(strname);
            ResponseStatus status = ResponseStatus.BadRequest;
            string strMessage = "Failed to parse request package.";
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            string strResponseData = "Bad Request";
            string strHeader = strArrHeader[4];
            try
            {
                byte[] byteHeader = new byte[HeaderLength];
                Array.Copy(byteData, 0, byteHeader, 0, HeaderLength);
                byte[] byteLength = new byte[IntLength];
                Array.Copy(byteData, HeaderLength, byteLength, 0, IntLength);
                int nBodyLen = BitConverter.ToInt32(byteLength, 0);
                byte[] byteBody = new byte[nBodyLen];
                Array.Copy(byteData, HeaderLength + IntLength, byteBody, 0, nBodyLen);
                strHeader = Encoding.UTF8.GetString(byteHeader);
                string strReqJsonBody = Encoding.UTF8.GetString(byteBody);
                if (theLog.IsDebugEnabled) theLog.Debug("Request Header : " + strHeader + ", Request Body : " + strReqJsonBody);
                if (!string.IsNullOrEmpty(strHeader))
                {
                    if (strHeader.Equals(strArrHeader[0], StringComparison.OrdinalIgnoreCase))
                    {
                        FileInfoResponse fileInfoResponse = new FileInfoResponse();
                        try
                        {
                            FileInfoRequest fileInfoReq = (FileInfoRequest)serializer.Deserialize(strReqJsonBody, typeof(FileInfoRequest));
                            if (fileInfoReq != null)
                            {
                                AzureFile tempAzureFiles = new AzureFile();
                                if (!dicAzureFiles.TryGetValue(fileInfoReq.FSHost, out tempAzureFiles))
                                {
                                    //if a new host excluded dicAzureFiles keys, will go into this branch
                                    //as Deployment method, open SMBproxy after opened File Info Server, so we have no dispose the case
                                    fileInfoResponse.Status = ResponseStatus.InvalidPath.ToString();
                                    fileInfoResponse.Message = "files of " + fileInfoReq.FSHost + " has not be cached. It often occurs when File Info Server launches after SMBproxy";
                                    strResponseData = serializer.Serialize(fileInfoResponse);
                                    if (theLog.IsDebugEnabled) theLog.Debug("Response Header : " + strHeader + ", Response Body : " + strResponseData);
                                    return ConstructResponse(strHeader, strResponseData);
                                }
                                Dictionary<string, int> dicKeywordsCount = new Dictionary<string, int>();
                                Dictionary<string, string> dicProperties = new Dictionary<string, string>();
                                if (dicAzureFiles[fileInfoReq.FSHost].GetFileInfo(fileInfoReq.FSHost, fileInfoReq.RelativePath, fileInfoReq.Keywords, ref dicKeywordsCount, ref dicProperties, ref status, ref strMessage))
                                {
                                    fileInfoResponse.Keywords = dicKeywordsCount;
                                    fileInfoResponse.Properties = dicProperties;
                                    fileInfoResponse.RelativePath = fileInfoReq.RelativePath;
                                }
                            }
                        }
                        catch (Exception fileInfoEx)
                        {
                            strMessage = fileInfoEx.Message;
                            theLog.Error("parse fileInfo failed: " + fileInfoEx.ToString());
                        }
                        fileInfoResponse.Status = status.ToString();
                        fileInfoResponse.Message = strMessage;
                        strResponseData = serializer.Serialize(fileInfoResponse);
                        if (theLog.IsDebugEnabled) theLog.Debug("Response Header : " + strHeader + ", Response Body : " + strResponseData);
                        return ConstructResponse(strHeader, strResponseData);
                    }
                    else if (strHeader.Equals(strArrHeader[1], StringComparison.OrdinalIgnoreCase)) // fresh file info cache request
                    {
                        TimerSettingRequest timerReq = (TimerSettingRequest)serializer.Deserialize(strReqJsonBody, typeof(TimerSettingRequest));
                        if (timerReq != null)
                        {
                            if (!dicAzureFiles.ContainsKey(timerReq.FSHost)) dicAzureFiles[timerReq.FSHost] = new AzureFile();
                            if (dicAzureFiles[timerReq.FSHost].CheckAndSetAzureTimerInfo(timerReq.FSHost, timerReq.Keywords, timerReq.SharedFolders, timerReq.IntervalTime))
                            {
                                if (!m_ParseredProxy.Contains(smbproxy)) m_ParseredProxy.Add(smbproxy);
                                dicAzureFiles[timerReq.FSHost].ProcessFileInfoTimer(ref status, ref strMessage);
                            }
                            else
                            {
                                status = ResponseStatus.Success;
                                strMessage = "Timer Setting is same with before, don't need change.";
                            }
                        }
                    }
                    else if (strHeader.Equals(strArrHeader[2], StringComparison.OrdinalIgnoreCase))
                    {
                        CheckTimerRequest timerStatusReq = (CheckTimerRequest)serializer.Deserialize(strReqJsonBody, typeof(CheckTimerRequest));
                        if (timerStatusReq != null) dicAzureFiles[timerStatusReq.FSHost].GetAzureTimerStatus(ref status, ref strMessage);
                    }
                    else if (strHeader.Equals(strArrHeader[3], StringComparison.OrdinalIgnoreCase))
                    {
                        HeartBeatResponse heartBeatResponse = null;
                        if (m_ParseredProxy.Contains(smbproxy)) heartBeatResponse = new HeartBeatResponse(HeartBeatStatus.Cached);
                        else heartBeatResponse = new HeartBeatResponse(HeartBeatStatus.NotCached);
                        strResponseData = serializer.Serialize(heartBeatResponse);
                        if (theLog.IsDebugEnabled) theLog.Debug("Response Header : " + strHeader + ", Response Body : " + strResponseData + ", Cached Proxy : " + string.Join(",", m_ParseredProxy));
                        return ConstructResponse(strHeader, strResponseData);
                    }
                }
            }
            catch (Exception ex)
            {
                status = ResponseStatus.Failed;
                strMessage = ex.Message;
                theLog.Error("parse package failed: " + ex.ToString());
            }
            StatusResponse statusResponse = new StatusResponse(status.ToString(), strMessage);
            strResponseData = serializer.Serialize(statusResponse);
            if(theLog.IsDebugEnabled) theLog.Debug("Response Header : " + strHeader + ", Response Body : " + strResponseData);
            return ConstructResponse(strHeader, strResponseData);
        }

        public static byte[] ConstructResponse(string strHeader, string strResponseData)
        {
            byte[] byteHeader = Encoding.UTF8.GetBytes(strHeader);
            byte[] byteResponse = Encoding.UTF8.GetBytes(strResponseData);
            byte[] byteLength = BitConverter.GetBytes(byteResponse.Length);
            byte[] lData = new byte[HeaderLength + IntLength + byteResponse.Length];
            if (byteHeader != null && byteHeader.Length == HeaderLength) Array.Copy(byteHeader, 0, lData, 0, HeaderLength);
            if (byteLength != null && byteLength.Length == IntLength) Array.Copy(byteLength, 0, lData, HeaderLength, IntLength);
            if (byteResponse != null && byteResponse.Length == byteResponse.Length) Array.Copy(byteResponse, 0, lData, HeaderLength + IntLength, byteResponse.Length);
            return lData;
        }
    }
}
