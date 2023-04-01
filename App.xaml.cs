using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace INTERFACE
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private byte[] _DEScipherText;
        private string key = "myunikey"; // ключ шифрования;
        private byte[] iv;
        private bool  _isAsymmetric = true;
        private RSAParameters RSAclosed_key;
        private RSAParameters RSAopen_key;
        private byte[] _RSAmessageBytes;
        private byte[] _signature;
        private void Button_Checked(object sender, EventArgs e)
        {
            RadioButton button = sender as RadioButton;
            if (button == null)
                return;
            if (button.Equals(SymRadioButton))
            {
                // RadioButton 1 checked
                _isAsymmetric = false;
            }
            else if (button.Equals(AsymRadioButton))
            {
                // RadioButton 2 checked
                _isAsymmetric = true;
            }

        }
        private void EncryptButton_Click(object sender, RoutedEventArgs e )
        {
            string plainText = InputTextBox.Text;
            switch (_isAsymmetric)
            {
                case true:
                    using (RSA rsa = RSA.Create())
                    {
                        RSAParameters privateKey = rsa.ExportParameters(true);
                        RSAParameters publicKey = rsa.ExportParameters(true);
                        RSAopen_key = publicKey;
                        RSAclosed_key = privateKey;
                        //шифрование с помощью открытого ключа
                        //string plainText = Console.ReadLine();
                        byte[] RSAencryptedData = RSAencrypt(Encoding.UTF8.GetBytes(plainText), publicKey);
                        _DEScipherText = RSAencryptedData;
                        OutputTextBox.Text = Convert.ToBase64String(RSAencryptedData);
                    }

                        //DIGITAL SIGNATURE
                        UnicodeEncoding byteConverter = new UnicodeEncoding();

                        // преобразуем сообщение в байты
                        byte[] messageBytes = byteConverter.GetBytes(plainText);
                        _RSAmessageBytes = messageBytes;
                        // Создаем цифровую подпись сообщения
                        using (RSACryptoServiceProvider rsaSign = new RSACryptoServiceProvider())
                        {
                            // импортируем закрытый ключ
                            rsaSign.ImportParameters(RSAclosed_key);

                            // подписываем сообщение
                            byte[] signature = rsaSign.SignData(messageBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                            _signature = signature;
                            DSA.Text = Convert.ToBase64String(signature);
                        }

                        break;


                case false:
                    byte[] cipherText = DESencrypt(plainText, key, out iv);
                    _DEScipherText= cipherText;
                    OutputTextBox.Text = Convert.ToBase64String(cipherText); // сохраняем зашифрованный текст в поле вывода
                    break;
            }
        }

        private void DecryptButton_Click(Object sender, RoutedEventArgs e)
        {
            InputTextBox.Text = Convert.ToBase64String(_DEScipherText);
            switch(_isAsymmetric)
            {
                case true:
                    byte[] RSAdecryptedData = RSAdecrypt(_DEScipherText, RSAclosed_key);
                    string RSAdecryptedText = Encoding.UTF8.GetString(RSAdecryptedData);
                    OutputTextBox.Text = RSAdecryptedText;
                break;

                case false:
                    string DESdecrypted = DESdecrypt(_DEScipherText, key, iv);
                    OutputTextBox.Text = DESdecrypted;
                    break;
            }
            
        }


        static byte[] DESencrypt(string plainText, string key, out byte[] _vector)
        {
            byte[] iv = new byte[8]; // инициализирующий вектор для алгоритма DES
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(iv); // генерируем инициализирующий вектор
            }
            _vector = iv;
            byte[] buffer = Encoding.UTF8.GetBytes(plainText); // преобразуем исходную строку в байтовый массив
            using (var des = new DESCryptoServiceProvider())
            {
                des.Key = Encoding.UTF8.GetBytes(key); // устанавливаем ключ шифрования
                des.IV = iv;  // устанавливаем инициализирующий вектор
                using (var stream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(stream, des.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(buffer, 0, buffer.Length); //шифруем данные
                        cryptoStream.FlushFinalBlock();
                    }
                    return stream.ToArray(); // возвращаем зашифрованный байтовый массив

                }
            }
        }

        static string DESdecrypt(byte[] cipherText, string key, byte[] vector)
        {
            byte[] iv = vector; // инициализирующий вектор для алгоритма DES
            using (var des = new DESCryptoServiceProvider())
            {
                des.Key = Encoding.UTF8.GetBytes(key);
                des.IV = iv;
                using (var stream = new MemoryStream(cipherText))
                {
                    using (var cryptoStream = new CryptoStream(stream, des.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (var streamReader = new StreamReader(cryptoStream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }

                }

            }
        }

        static byte[] RSAencrypt(byte[] data, RSAParameters publicKey)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKey);
                return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            }
        }

        static byte[] RSAdecrypt(byte[] data, RSAParameters privateKey)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(privateKey);
                return rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);
            }
        }

        private void Reset_Click(object sender, EventArgs e)
        {
            InputTextBox.Text = string.Empty;
            OutputTextBox.Text = string.Empty;
            DSA.Text = string.Empty;
        }

    }
}
