using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

namespace SocketServer
{
    public interface ICache<TKey, TValue>
    {
        int Count { get; }
        List<TKey> Keys { get; }
        Dictionary<TKey, TValue> Dic { get; }
        TValue Get(TKey key);
        bool Set(TKey key, TValue val);
        bool Delete(TKey key);
        void Update(ConcurrentCache<TKey, TValue> rCache);
        void Clear();
        bool TryGet(TKey key, ref TValue oKey);
    }

    public class ConcurrentCache<TKey, TValue> : ICache<TKey, TValue>
    {
        private ReaderWriterLockSlim rwLock = new ReaderWriterLockSlim();
        private Dictionary<TKey, TValue> m_dicCache = new Dictionary<TKey, TValue>();

        ~ConcurrentCache()
        {
            if (rwLock != null) { rwLock.Dispose(); }
        }

        public int Count
        {
            get
            {
                rwLock.EnterReadLock();
                try { return m_dicCache.Count; }
                finally { rwLock.ExitReadLock(); }
            }
        }

        public List<TKey> Keys
        {
            get
            {
                rwLock.EnterReadLock();
                try { return m_dicCache.Keys.ToList<TKey>(); }
                finally { rwLock.ExitReadLock(); }
            }
        }

        public Dictionary<TKey, TValue> Dic
        {
            get
            {
                rwLock.EnterReadLock();
                try { return new Dictionary<TKey, TValue>(m_dicCache); }
                finally { rwLock.ExitReadLock(); }
            }
        }

        public TValue Get(TKey key)
        {
            TValue defaultVal;
            rwLock.EnterReadLock();
            try
            {
                bool bIsExist = m_dicCache.TryGetValue(key, out defaultVal);
                if(bIsExist) { return defaultVal; }
                else { return default(TValue); }
            }
            finally { rwLock.ExitReadLock(); }
        }

        public bool TryGet(TKey key, ref TValue oKey)
        {
            rwLock.EnterReadLock();
            try { return m_dicCache.TryGetValue(key, out oKey); }
            finally { rwLock.ExitReadLock(); }
        }

        public bool Set(TKey key, TValue val)
        {
            bool bIsSuccess = false;
            rwLock.EnterWriteLock();
            try
            {
                m_dicCache[key] = val;
                bIsSuccess = true;
            }
            finally { rwLock.ExitWriteLock(); }
            return bIsSuccess;
        }

        public bool Delete(TKey key)
        {
            bool bIsSuccess = false;
            rwLock.EnterWriteLock();
            try { bIsSuccess = m_dicCache.Remove(key); }
            catch(Exception e) { System.Diagnostics.Trace.WriteLine(string.Format("delete key '{0}' failed, {1}", key.ToString(), e.Message)); }
            finally { rwLock.ExitWriteLock(); }

            return bIsSuccess;
        }

        public void Update(ConcurrentCache<TKey, TValue> rCache)
        {
            Dictionary<TKey, TValue> rDic = rCache.Dic;
            rwLock.EnterWriteLock();
            try
            {
                m_dicCache.Clear();
                m_dicCache = rDic;
            }
            finally { rwLock.ExitWriteLock(); }
        }

        public void Clear()
        {
            rwLock.EnterWriteLock();
            try { m_dicCache.Clear(); }
            finally { rwLock.ExitWriteLock(); }
        }
    }
}
