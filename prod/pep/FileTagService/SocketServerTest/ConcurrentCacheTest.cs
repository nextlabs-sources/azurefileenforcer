using Microsoft.VisualStudio.TestTools.UnitTesting;
using SocketServer;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SocketServer.Tests
{
    [TestClass()]
    public class ConcurrentCacheTest
    {
        public SocketServer.ConcurrentCache<TKey, TValue> GetInstance<TKey, TValue>()
        {
            return new ConcurrentCache<TKey, TValue>();
        }

        [TestMethod()]
        public void BaseTest()
        {
            List<Task> tasks = new List<Task>();
            ConcurrentCache<int, Int32> cache = GetInstance<int, Int32>();
            
            for(int i = 0; i < 100; i++)
            {
                int indexCopy = i;
                tasks.Add(Task.Run(() => cache.Set(indexCopy, indexCopy * indexCopy)));
            }

            Task.WaitAll(tasks.ToArray());
            Assert.AreEqual(100, cache.Count);
            for(int i = 0; i < 100; i++)
            {
                Assert.AreEqual(i * i, cache.Get(i));
            }
        }

        [TestMethod()]
        public void DeleteTest()
        {
            List<Task> insertTasks = new List<Task>();
            List<Task> deleteTasks = new List<Task>();
            ConcurrentCache<int, Int32> cache = GetInstance<int, Int32>();

            for (int i = 0; i < 100; i++)
            {
                int indexCopy = i;
                insertTasks.Add(Task.Run(() => cache.Set(indexCopy, indexCopy * indexCopy)));
            }

            Task.WaitAll(insertTasks.ToArray());
            Assert.AreEqual(100, cache.Count);
            for (int i = 0; i < 100; i++)
            {
                int index = i;
                deleteTasks.Add(Task.Run(() => cache.Delete(index)));
            }

            Task.WaitAll(deleteTasks.ToArray());
            Assert.AreEqual(0, cache.Count);
        }
    }
}