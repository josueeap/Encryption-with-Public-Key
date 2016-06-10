using System;
using System.Web;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace EncryptWithPublicKey
{
    [Serializable]
    public class EncryptKey
    {
        public string PublicKey { get; set; }
    }

    public static class EncryptPKey
    {
        private static bool _optimalAsymmetricEncryptionPadding = false;

        public static string EncryptText(string text, string publicKey)
        {
            int keySize = 0;
            string publicKeyXml = "";

            GKFEString(publicKey, out keySize, out publicKeyXml);

            var encrypted = Encrypt(Encoding.UTF8.GetBytes(text), keySize, publicKeyXml);
            return Convert.ToBase64String(encrypted);
        }

        private static byte[] Encrypt(byte[] data, int kSize, string pXml)
        {
            if (data == null || data.Length == 0) throw new ArgumentException("Data are empty", "data");
            int maxLength = getMl(kSize);
            if (data.Length > maxLength) throw new ArgumentException(String.Format("Maximum data length is {0}", maxLength), "data");
            if (!IsKSV(kSize)) throw new ArgumentException("Key size is not valid", "keySize");
            if (String.IsNullOrEmpty(pXml)) throw new ArgumentException("Key is null or empty", "publicKeyXml");

            using (var provider = new RSACryptoServiceProvider(kSize))
            {
                provider.FromXmlString(pXml);
                return provider.Encrypt(data, _optimalAsymmetricEncryptionPadding);
            }
        }


        public static int getMl(int kSize)
        {
            if (_optimalAsymmetricEncryptionPadding)
            {
                return ((kSize - 384) / 8) + 7;
            }
            return ((kSize - 384) / 8) + 37;
        }

        public static bool IsKSV(int kSize)
        {
            return kSize >= 384 &&
                    kSize <= 16384 &&
                    kSize % 8 == 0;
        }

        private static string IKIEString(string pKey, int kSize)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(kSize.ToString() + "!" + pKey));
        }

        private static void GKFEString(string rkey, out int kSize, out string xmlK)
        {
            kSize = 0;
            xmlK = "";

            if (rkey != null && rkey.Length > 0)
            {
                byte[] keyBytes = Convert.FromBase64String(rkey);
                var stringKey = Encoding.UTF8.GetString(keyBytes);

                if (stringKey.Contains("!"))
                {
                    var splittedValues = stringKey.Split(new char[] { '!' }, 2);

                    try
                    {
                        kSize = int.Parse(splittedValues[0]);
                        xmlK = splittedValues[1];
                    }
                    catch (Exception e) { }
                }
            }
        }
    }
}
