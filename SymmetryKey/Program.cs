using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SymmetryKey
{
    class Program
    {
        static void Main(string[] args)
        {
            using (Aes symmetricKey = Aes.Create())
            {
                symmetricKey.GenerateIV();
                string large = new string('d', 30 * 512 * 1024);
                string plainText = large;
                string encryptedText = null;
                string decryptText = null;
                Invoke(() => encryptedText = EncryptWithSymmetryKey(plainText, symmetricKey.Key, symmetricKey.IV));
                Invoke(() => decryptText = DecryptWithSymmetryKey(encryptedText, symmetricKey.Key, symmetricKey.IV));

                if (plainText.Equals(decryptText))
                {
                    Console.WriteLine("Lalalala");
                }

                Console.ReadKey();
            }
        }

        static void Invoke(Action action)
        {
            Stopwatch stopWatch = new Stopwatch();
            stopWatch.Start();

            action();

            stopWatch.Stop();
            TimeSpan ts = stopWatch.Elapsed;

            // Format and display the TimeSpan value.
            string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}.{3:00}",
                ts.Hours, ts.Minutes, ts.Seconds,
                ts.Milliseconds);
            Console.WriteLine(elapsedTime);
        }

        public static string EncryptWithSymmetryKey(string plainText, byte[] key, byte[] IV)
        {
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            using (Aes symmetricKey = Aes.Create())
            {
                using (ICryptoTransform encryptor = symmetricKey.CreateEncryptor(key, IV))
                {
                    using (MemoryStream memoryStream = new MemoryStream())
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                            cryptoStream.FlushFinalBlock();
                            byte[] cipherTextBytes = memoryStream.ToArray();
                            return Convert.ToBase64String(cipherTextBytes);
                        }
                    }
                }
            }
        }

        public static string DecryptWithSymmetryKey(string encryptedText, byte[] key, byte[] IV)
        {
            byte[] blob = Convert.FromBase64String(encryptedText);
            byte[] plainData = new byte[blob.Length];

            int length = DecryptInternal(encryptedText, key, IV, plainData);

            return Encoding.UTF8.GetString(plainData, 0, length);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1804:RemoveUnusedLocals", MessageId = "dummy")]
        internal unsafe static int DecryptInternal(string encryptedText, byte[] key, byte[] IV, byte[] plainData)
        {
            if (encryptedText == null) throw new ArgumentNullException("encryptedText");

            byte[] cipherTextBytes = Convert.FromBase64String(encryptedText);

            using (Aes symmetricKey = Aes.Create())
            {
                using (ICryptoTransform decryptor = symmetricKey.CreateDecryptor(key, IV))
                {
                    using (MemoryStream memoryStream = new MemoryStream(cipherTextBytes))
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                        {
                            byte[] plainTextBytes = new byte[cipherTextBytes.Length];
                            int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);

                            fixed (byte* dummy = plainTextBytes)
                            {
                                    Array.Copy(plainTextBytes, plainData, decryptedByteCount);
                                    return decryptedByteCount;
                            }
                        }
                    }
                }
            }
        }
    }
}
