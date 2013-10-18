using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Security.Cryptography;
using System.IO;
using System.Windows;
using System.Security.Cryptography;
using System.Text;

namespace RSAEncryptDemo.Common
{
    public class RsaDataEncryptHelper
    {
        #region Property
        private int MaxBlockSize = 70;
        #endregion

        #region Action
        private string GetEncryPublicKey()
        {
            string publicKey = string.Empty;
            using (var cerStream = Application.GetResourceStream(new Uri("/RSAEncryptDemo;component/Files/mojicert.cer", UriKind.RelativeOrAbsolute)).Stream)
            {
                byte[] cerBuffer = new byte[cerStream.Length];
                cerStream.Read(cerBuffer, 0, cerBuffer.Length);
                System.Security.Cryptography.X509Certificates.X509Certificate cer = new System.Security.Cryptography.X509Certificates.X509Certificate(cerBuffer);
                publicKey = cer.GetPublicKeyString();
            }
            return publicKey;
        }

        private System.Security.Cryptography.RSAParameters ConvertPublicKeyToRsaInfo()
        {
            System.Security.Cryptography.RSAParameters RSAKeyInfo;
            using (var cerStream = Application.GetResourceStream(new Uri("/RSAEncryptDemo;component/Files/DemoPublicKey.cer", UriKind.RelativeOrAbsolute)).Stream)
            {
                byte[] cerBuffer = new byte[cerStream.Length];
                cerStream.Read(cerBuffer, 0, cerBuffer.Length);
                System.Security.Cryptography.X509Certificates.X509Certificate cer = new System.Security.Cryptography.X509Certificates.X509Certificate(cerBuffer);
                RSAKeyInfo = X509PublicKeyParser.GetRSAPublicKeyParameters(cer.GetPublicKey());                    
            }
            return RSAKeyInfo;
        }

        public string GetEncryptBase64String(string needEncryptContent)
        {
            string encryptBase64Str = string.Empty;

            if (!CheckIsNeedSpiltMorePartEncypt(needEncryptContent))
            {
                #region Does't Need Data Encrypt With Spilt Content
                byte[] encryptBytes = DataEncryptWithRsa(System.Text.Encoding.UTF8.GetBytes(needEncryptContent));
                //RSA Data Encrypt Data Convert To Base64 Format 
                encryptBase64Str = Convert.ToBase64String(encryptBytes);                  
                #endregion
            }
            else
            {
                #region Need Spilt More Part Data Encrypt With RSA
                using (MemoryStream PlaiStream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(needEncryptContent)))
                using (MemoryStream CrypStream = new MemoryStream())
                {
                    Byte[] Buffer = new Byte[MaxBlockSize];
                    int BlockSize = PlaiStream.Read(Buffer, 0, MaxBlockSize);

                    while (BlockSize > 0)
                    {
                        Byte[] ToEncrypt = new Byte[BlockSize];
                        Array.Copy(Buffer, 0, ToEncrypt, 0, BlockSize);

                        Byte[] Cryptograph = DataEncryptWithRsa(ToEncrypt);
                        CrypStream.Write(Cryptograph, 0, Cryptograph.Length);
                        BlockSize = PlaiStream.Read(Buffer, 0, MaxBlockSize);
                    }
                    encryptBase64Str=Convert.ToBase64String(CrypStream.ToArray());
                }
                #endregion
            }

            return encryptBase64Str;
        }

        private bool CheckIsNeedSpiltMorePartEncypt(string needEncryptContent)
        {
            bool isNeedSpilt = false;

            byte[] inData = System.Text.Encoding.UTF8.GetBytes(needEncryptContent);
            int dataLength = inData.Length >> 2;
            int leftOver = inData.Length & 0x3;

            if (leftOver != 0)// length not multiples of 4
                dataLength++;

            if (dataLength > MaxBlockSize)
                isNeedSpilt = true;

            return isNeedSpilt;
        }

        private byte[] DataEncryptWithRsa(byte[] needEncryptContentBytes)
        {
            System.Security.Cryptography.RSAParameters RSAKeyInfo = ConvertPublicKeyToRsaInfo();
            BigInteger bi_e = new BigInteger(RSAKeyInfo.Exponent);
            BigInteger bi_n = new BigInteger(RSAKeyInfo.Modulus);

            BigInteger bi_data = new BigInteger(System.Text.Encoding.UTF8.GetBytes("Hello World"));//
            BigInteger bi_encrypted = bi_data.modPow(bi_e, bi_n);
            return bi_encrypted.getBytes();
        }

        public string UseSystemRsaDataEncrypt(string needEncryptContent)
        {
            #region Use System Default Encrypt Mether Handler Data
            RSAParameters rsaDefineRap = ConvertPublicKeyToRsaInfo();
            string modulus = Convert.ToBase64String(rsaDefineRap.Modulus);
            string exponent = Convert.ToBase64String(rsaDefineRap.Exponent);

            string publickey = @"<RSAKeyValue><Modulus>" + modulus + "</Modulus><Exponent>" + exponent + "</Exponent></RSAKeyValue>";
            RSACryptoServiceProvider rsaCrypt = new System.Security.Cryptography.RSACryptoServiceProvider();
            rsaCrypt.FromXmlString(publickey); 

            byte[] contentBytes = System.Text.Encoding.UTF8.GetBytes(needEncryptContent);
            int maxBlockSize = rsaCrypt.KeySize / 8 - 11;

            if (contentBytes.Length <= maxBlockSize)
                return Convert.ToBase64String(rsaCrypt.Encrypt(contentBytes, false));

            using (MemoryStream PlaiStream = new MemoryStream(contentBytes))
            using (MemoryStream CrypStream = new MemoryStream())
            {
                Byte[] Buffer = new Byte[maxBlockSize];
                int BlockSize = PlaiStream.Read(Buffer, 0, maxBlockSize);

                while (BlockSize > 0)
                {
                    #region Merge Spilt More Part About Rsa Encrypt String
                    Byte[] ToEncrypt = new Byte[BlockSize];
                    Array.Copy(Buffer, 0, ToEncrypt, 0, BlockSize);

                    Byte[] Cryptograph = DataEncryptWithRsa(ToEncrypt);
                    CrypStream.Write(Cryptograph, 0, Cryptograph.Length);
                    BlockSize = PlaiStream.Read(Buffer, 0, maxBlockSize);
                    #endregion
                }

                byte[] encryBytes=  rsaCrypt.Encrypt(System.Text.Encoding.UTF8.GetBytes("Hello World"), false);
                return Convert.ToBase64String(encryBytes);
            }
            #endregion
        }
        #endregion
    }
}
