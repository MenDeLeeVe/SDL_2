using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

class Program
{
    const string Alphabet = "abcdefghijklmnopqrstuvwxyz";
    const int PasswordLength = 5;

    static void Main()
    {
        List<string> hashes = new List<string>
        {
            "1115dd800feaacefdf481f1f9070374a2a81e27880f187396db67958b207cbad",
            "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
            "74e1bb62f8dabb8125a58852b63bdf6eaef667cb56ac7f7cdba6d7305c50a22f",
            "7a68f09bd992671bb3b19a5e70b7827e"
        };

        Console.WriteLine("Введите количество потоков:");
        if (!int.TryParse(Console.ReadLine(), out int numThreads) || numThreads <= 0)
        {
            Console.WriteLine("Ошибка: введите положительное целое число.");
            return;
        }

        List<string> passwords = GeneratePasswords();
        Console.WriteLine($"Пароли были сгенерированы, всего: {passwords.Count}");

        foreach (var hash in hashes)
        {
            Console.WriteLine($"\nПоиск пароля для хэша {hash} в многопоточном режиме (потоки: {numThreads}):");
            BruteForceMultiThread(hash, hash, passwords, numThreads);
        }
    }

    static List<string> GeneratePasswords()
    {
        List<string> passwords = new List<string>();
        char[] password = new char[PasswordLength];
        Generate(passwords, password, 0);
        return passwords;
    }

    static void Generate(List<string> passwords, char[] password, int pos)
    {
        if (pos == PasswordLength)
        {
            passwords.Add(new string(password));
            return;
        }
        foreach (char c in Alphabet)
        {
            password[pos] = c;
            Generate(passwords, password, pos + 1);
        }
    }

    static (bool, bool) CheckPassword(string password, string targetMD5, string targetSHA256)
    {
        using (var md5 = MD5.Create())
        {
            string md5Str = BitConverter.ToString(md5.ComputeHash(Encoding.UTF8.GetBytes(password))).Replace("-", "").ToLowerInvariant();
            bool md5Match = (md5Str == targetMD5);

            using (var sha256 = SHA256.Create())
            {
                string sha256Str = BitConverter.ToString(sha256.ComputeHash(Encoding.UTF8.GetBytes(password))).Replace("-", "").ToLowerInvariant();
                bool sha256Match = (sha256Str == targetSHA256);

                return (md5Match, sha256Match);
            }
        }
    }

    static void BruteForceMultiThread(string targetMD5, string targetSHA256, List<string> passwords, int numThreads)
    {
        var start = DateTime.Now;
        bool found = false;
        object lockObj = new object();

        Parallel.ForEach(Partitioner.Create(0, passwords.Count, passwords.Count / numThreads), new ParallelOptions { MaxDegreeOfParallelism = numThreads }, (range, state) =>
        {
            for (int i = range.Item1; i < range.Item2; i++)
            {
                if (found) break;

                var (md5Match, sha256Match) = CheckPassword(passwords[i], targetMD5, targetSHA256);
                if (md5Match || sha256Match)
                {
                    lock (lockObj)
                    {
                        if (!found)
                        {
                            Console.WriteLine($"Найден пароль: {passwords[i]} (MD5 совпадение: {md5Match}, SHA-256 совпадение: {sha256Match})");
                            found = true;
                            state.Stop();
                        }
                    }
                }
            }
        });

        var end = DateTime.Now;
        Console.WriteLine($"Многопоточный режим завершён за {end - start}");
    }
}