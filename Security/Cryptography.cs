using System;
using System.Configuration;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SecurityApp
{
    public class Cryptography
    {
        private string SecretKey = ConfigurationManager.AppSettings.Get("SecretKey"); //"6c7nGrky/ehjM40Ivk3p3+OeoEm9r7NCzmWexUULaa4=";  // abcd1234(SHA256)
        private string HmacKey = ConfigurationManager.AppSettings.Get("HmacKey"); //"7dEeX8uWxLLvxnUgKJipm80AiVKZKYyETsXBffxvgaY="; // 201904151653ggit2u.com(SHA256)
        private const string DECRYPT = "decrypt";
        private const string ENCRYPT = "encrypt";
        private const string SHA1 = "SHA1";
        private const string SHA256 = "SHA256";
        private const string SHA512 = "SHA512";
        private const string MD5 = "MD5";
        private const string PrivateKeyCert = "BwIAAACkAABSU0EyAAgAAAEAAQD18ViKi9UOVlRyPcf43VnGKOAHuQcny9KmksAn8lT3einakEDB9ypJTFpL0ZcVMeAla7V6auiIsJqOqY7x27xdULccfG8jSOvaLZBvRhmWX/KgGuuxeCCaSbYNlT6Un2gj4+ikLASNxcC55sa4uxZivBlaKX713r7YW8zs18OfaIQbDzspY4i/upAa+L15qKektZtWofF3wrMAWSt4uErHeLjVGNdIPWAAFoL4nJr3Y7uPJso/gVoE0tGNsHVw91o9lYDEaDFWutlBgtgOY+GUv0sZV0aLNwm1a0BBmTAF7kbUoVk9GOXpw5RbQ+zWYDUtUfhKeNKwWOeexs94DqWvH+TJunhxvHU83TaPrBZ9gPj3zDRpdRGLk31ZlXUYy9Y4v5W091QPhK5BHoobmTh7eUnZTGbwK3NR70o7PbRNkoNMnySlTG5ipg2DkuD12a7p9Ap12KiSuZ6IVtPBkUzR4UK0cv99Vmu1glG6g3dukTLxK9vDT97HdKpiwE4GrudrRw4AI9uIyCxRg6XQTH59CjS2m0qT2LkCu/TBBMgMfgqWQRAupYnVVEKLlOeYHzHnYiy1IQPHEsQp6/TFuGPDzpreu9MUIf9jnhrsVJTpyVchQQLVfFCMA6IgP5qIyrrOCw5KY+TaHP2pYXQqYGH2WpvnCIXfVZnERkE6FDEVwqHIHgWzdc3JiqHxHlyAAjhGhm3tVlAm+zrpHSvnSbPZWq5lAiX0u5zkVevNGjNdXdxKicLWbFo7HnppnPRQZhSAu8KQrX8DRc+Zjd5470cZeDoaFd54qN8wqAtiFfeCuMckPatvdToL78+Jg2sA5zqGBmMiLatTeYeickaK0MTQM6gIdaAMwEvnURd7NYsJbCxGHkC/Z01tAJh61jvwbfMsSa97Gu5iSsK2YBGKbw83bxU7dA5rPIYk+XedbLJTr3jn5Nw8wXhYHfK1RGsGAyrl+U3SAzv4Q2oJ+P7gavPMwUhBPBLMFYxb2kHXHxszjDNZilzt6Z62EcmjtUPjeIme4GqUd+X7zlti+ymZa9im5MPZfMOA67rhx8OJ7/SmSR9DRzCcCYapHlPTO5zz99LesfsJYOnXAGOkza588ZEMe8ezyVgCsDeyu3H4EL4y9Guq1iOgOjBbuKKo4Ye3bdA6DoqLFO9eh0+XaqsEm/GlLrWZ24Hm4XxsQ2W0IdsPtDVqZ0LNHwYQHeRkb/gT3hQfdkm2iwbnSWuRF1fnG4KYexR25ftTb6QN/P+47U49MDiBG6kA2v5xGw39iNHj8b/+vlrwMo6+d087wyCHGbFF2PXdBRjBA2ob/SeS8kkNl2+8FnZfGV05SXBObHn5GkZoIZgmeiKH+JTFjS/0rlUkoQ1/BNB1bmL4mLnD0Pn4IsArwQ8DIRKoWijxNBQR/Cpveb4Nu543Ggpataw87qt4RO9mTsDFUt/t6B/Aoo3BECrWrBuelkQM5nZkyiy34IOH0XFv0UGODKnGSe/UJWmgNdug+XtRIyuXOEPcNqKCHzhlM1H2HUHTT6nqSqNYUmo=";

        public Cryptography()
        {
        }

        public virtual string SHA1MessageHash(string message)
        {
            return Hashing(SHA1, message);
        }

        public virtual string SHA256MessageHash(string message)
        {
            return Hashing(SHA256, message);
        }

        public virtual string SHA512MessageHash(string message)
        {
            return Hashing(SHA512, message);
        }

        public virtual string MD5MessageHash(string message)
        {
            return Hashing(MD5, message);
        }

        public virtual string Hashing(string algorithm, string message)
        {
            string hashed = null;
            dynamic HashAlgorithm;

            switch(algorithm)
            {
                case SHA1:
                    HashAlgorithm = new SHA1Managed();
                    break;
                case SHA256:
                    HashAlgorithm = new SHA256Managed();
                    break;
                case SHA512:
                    HashAlgorithm = new SHA512Managed();
                    break;
                case MD5:
                    HashAlgorithm = new MD5CryptoServiceProvider();
                    break;
                default:
                    throw new Exception("Invalid hashing algorithm");
            }

            byte[] bufferHashed = HashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(message));
            hashed = ConvertByteToBase64String(bufferHashed);
            HashAlgorithm.Clear();
            HashAlgorithm = null;

            return hashed;
        }

        public virtual string TripleDES_Encryptor(string plainMessage, byte[] secretKey = null)
        {
            return TripleDESCrypto(plainMessage, ENCRYPT, secretKey);
        }

        public virtual string TripleDES_Decryptor(string ciphterText, byte[] secretKey = null)
        {
            return TripleDESCrypto(ciphterText, DECRYPT, secretKey);
        }

        protected virtual string TripleDESCrypto(string str,string type,byte[]secretKey)
        {
            string data = null;
            ICryptoTransform cryptoEngine = null;
            byte[] inputBuffer = null;
            byte[] results;
            byte[] defaultSecret = secretKey?.Length > 0 ? secretKey : Encoding.UTF8.GetBytes(SecretKey);
            byte[] secretkey = new byte[24]; // its because c# using 24 bytes to do encription for 3DES
            Array.Copy(defaultSecret, secretkey, 24);

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider
            {
                //set the secret key for the tripleDES algorithm
                Key = secretkey,
                //mode of operation. there are other 4 modes. We choose ECB(Electronic code Book)
                Mode = CipherMode.ECB,
                //padding mode(if any extra byte added)
                Padding = PaddingMode.PKCS7
            };

            try
            {
                switch (type)
                {
                    case DECRYPT:
                        cryptoEngine = tdes.CreateDecryptor();
                        inputBuffer = ConvertBase64StringToByte(str);
                        results = cryptoEngine.TransformFinalBlock(inputBuffer, 0, inputBuffer.Length);
                        data = Encoding.UTF8.GetString(results);
                        break;
                    case ENCRYPT:
                    default:
                        cryptoEngine = tdes.CreateEncryptor();
                        inputBuffer = Encoding.UTF8.GetBytes(str);
                        results = cryptoEngine.TransformFinalBlock(inputBuffer, 0, inputBuffer.Length);
                        data = ConvertByteToBase64String(results);
                        break;
                }

                return data;
            }
            catch
            {
                throw new Exception("Unable to encrypt/decrypt due to data input mismatch. Input => "+ str);
            }
            finally
            {
                tdes.Clear();
            }
        }

        public virtual string RSADigitalSignatureSHA1(string DataToSign)
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes(DataToSign);
            RSACryptoServiceProvider RSACrypto = new RSACryptoServiceProvider(2048);

            try
            {
                //RSACrypto.FromXmlString(PrivateKeyXML);
                RSACrypto.ImportCspBlob(Convert.FromBase64String(PrivateKeyCert));
                return ConvertByteToBase64String(RSACrypto.SignData(dataToEncrypt, SHA1));
            }
            catch
            {
                return string.Empty;
            }
            finally
            {
                RSACrypto.Clear();
            }
        }

        public virtual bool VerifyRSADigitalSignatureSHA1(string OriginalData, string SignatureData)
        {
            RSACryptoServiceProvider RSAVerifier = new RSACryptoServiceProvider(2048);
            try
            {
                //RSAVerifier.FromXmlString(PrivateKeyXML);
                RSAVerifier.ImportCspBlob(Convert.FromBase64String(PrivateKeyCert));
                byte[] signedData = ConvertBase64StringToByte(SignatureData);

                return RSAVerifier.VerifyData(Encoding.UTF8.GetBytes(OriginalData), SHA1, signedData);
            }
            catch
            {
                return false;
            }
            finally
            {
                RSAVerifier.Clear();
            }
        }

        public virtual string CreateSaltKey(int size = 5)
        {
            //generate a cryptographic random number
            using (var provider = new RNGCryptoServiceProvider())
            {
                var buff = new byte[size];
                provider.GetBytes(buff);

                // Return a Base64 string representation of the random number
                return ConvertByteToBase64String(buff);
            }
        }

        public virtual string PasswordHash(string password, string saltkey, string passwordFormat = SHA512)
        {
            return CreateHash(Encoding.UTF8.GetBytes(string.Concat(password, saltkey)), passwordFormat);
        }

        public virtual string CreateHash(byte[] data, string hashAlgorithm)
        {
            if (string.IsNullOrEmpty(hashAlgorithm))
                throw new ArgumentNullException(nameof(hashAlgorithm));

            var algorithm = HashAlgorithm.Create(hashAlgorithm);
            if (algorithm == null)
                throw new ArgumentException("Unrecognized hash name");

            var hashByteArray = algorithm.ComputeHash(data);
            return BitConverter.ToString(hashByteArray).Replace("-", "");
        }

        public bool CreateBufferFile(string fileName, string secret)
        {
            bool success = false;
            try
            {
                using (FileStream stream = new FileStream(fileName, FileMode.Create)) //FileMode.Create will overwrite the file if it exist!
                {
                    using (BinaryWriter writer = new BinaryWriter(stream))
                    {
                        byte[] buf = ConvertBase64StringToByte(secret);
                        writer.Write(buf);
                        writer.Close();
                    }
                    stream.Close();
                }
                return true;
            }
            catch(Exception ex)
            {
                return success;
            }

        }

        public string GenerateSecretKey(string algorithm, string msg)
        {
            return Hashing(algorithm, msg);
        }
        
        public virtual byte[] HMACSignatures(string algorithm, string msg, string secret)
        {
            dynamic Hmac;
            if (string.IsNullOrWhiteSpace(secret))
                secret = HmacKey;

            byte[] key = ConvertBase64StringToByte(secret); // secret key MUST in base64 string(Hashed string)

            switch (algorithm)
            {
                case SHA1:
                    Hmac = new HMACSHA1(key);
                    break;
                case SHA256:
                    Hmac = new HMACSHA256(key);
                    break;
                case SHA512:
                    Hmac = new HMACSHA512(key);
                    break;
                default:
                    throw new Exception("Invalid hashing algorithm");
            }
            
            byte[] result = Hmac.ComputeHash(Encoding.UTF8.GetBytes(msg));
            Hmac.Clear();
            Hmac = null;

            return result;
        }

        public virtual string ConvertByteToBase64String(byte[] input)
        {
            return Convert.ToBase64String(input);
        }

        public virtual byte[] ConvertBase64StringToByte(string input)
        {
            return Convert.FromBase64String(input);
        }

        public virtual string ConvertByteToHex(byte[] input)
        {
            return BitConverter.ToString(input).Replace("-", "").ToLower();
        }

        public virtual bool HMACVerify(string algorithm, string msg, string signatures, string secret)
        {
            if (string.IsNullOrWhiteSpace(secret))
                secret = HmacKey;

            return signatures == ConvertByteToHex(HMACSignatures(algorithm, msg, secret));
        }
    }
}
