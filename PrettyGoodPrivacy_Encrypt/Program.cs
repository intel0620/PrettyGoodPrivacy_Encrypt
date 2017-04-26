using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg.OpenPgp.Examples;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrettyGoodPrivacy_Encrypt
{
    class Program
    {
        static void Main(string[] args)
        { 
            //Public 1 檔案加密
            string encryptFileName = @"D:/PGP/b.txt";//加密後產生的檔案
            string inputFileName = @"D:/PGP/a.txt"; //未加密的檔案
            string encKeyFileName = @"D:/PGP/Sample_pub.asc"; //公鑰
            bool armor = true;
            bool withIntegrityCheck = false;
            try
            {
                EncryptFile(encryptFileName, inputFileName, encKeyFileName, armor, withIntegrityCheck);
                Console.WriteLine("加密成功");
            }
            catch (Exception e)
            {
                Console.WriteLine("加密失敗" + e.Message);
            }
            Console.ReadLine();
        }

        //外部呼叫的 method
        public static void EncryptFile(
             string outputFileName,//加密後輸出檔案名稱位置
             string inputFileName, //欲加密檔案名稱位置
             string encKeyFileName,//提供加密的 public key 檔名及位置
             bool armor,           //範例預設為true
             bool withIntegrityCheck//範例預設為false
             )
        {
            PgpPublicKey encKey = PgpExampleUtilities.ReadPublicKey(encKeyFileName);

            using (Stream output = File.Create(outputFileName))
            {
                EncryptFile(output, inputFileName, encKey, armor, withIntegrityCheck);
            }
        }

        //內部的實作參照官方範例
        private static void EncryptFile(
            Stream outputStream,
            string fileName,
            PgpPublicKey encKey,
            bool armor,
            bool withIntegrityCheck)
        {
            if (armor)
            {
                outputStream = new ArmoredOutputStream(outputStream);
            }

            try
            {
                byte[] bytes = PgpExampleUtilities.CompressFile(fileName, CompressionAlgorithmTag.Zip);

                PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator(
                    SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
                encGen.AddMethod(encKey);

                Stream cOut = encGen.Open(outputStream, bytes.Length);

                cOut.Write(bytes, 0, bytes.Length);
                cOut.Close();

                if (armor)
                {
                    outputStream.Close();
                }
            }
            catch (PgpException e)
            {
                Console.Error.WriteLine(e);

                Exception underlyingException = e.InnerException;
                if (underlyingException != null)
                {
                    Console.Error.WriteLine(underlyingException.Message);
                    Console.Error.WriteLine(underlyingException.StackTrace);
                }
            }
        }
    }
}
