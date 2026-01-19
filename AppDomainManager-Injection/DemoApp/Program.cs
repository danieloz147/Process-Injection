using System;
using System.Threading.Tasks;

namespace DemoApp
{
    internal static class Program
    {   
        public static async Task Main(string[] args)
        {
            while (true)
            {
                var date = DateTime.UtcNow;
                Console.WriteLine($"The time is {date:T}.");

                await Task.Delay(TimeSpan.FromSeconds(10));
            }
        }
    }
}
