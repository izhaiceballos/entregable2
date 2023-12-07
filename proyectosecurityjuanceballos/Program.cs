using System;
using System.Text;
using System.IO;
using System.Security.Cryptography;

class Program
{
    static void Main()
    {
        Console.WriteLine("Ingrese un número de tarjeta:");

        string numeroTarjeta = "";
        ConsoleKeyInfo key;

        do
        {
            key = Console.ReadKey(true);
            if (numeroTarjeta.Length < 16)
            {
                if (char.IsDigit(key.KeyChar))
                {
                    numeroTarjeta += key.KeyChar;

                    if (numeroTarjeta.Length <= 12)
                    {
                        Console.Write("*");
                    }
                    else { Console.Write(key.KeyChar); }
                }
                else if (key.Key == ConsoleKey.Backspace && numeroTarjeta.Length > 0)
                {
                    numeroTarjeta = numeroTarjeta.Substring(0, numeroTarjeta.Length - 1);
                    Console.Write("\b \b"); // Borra el último carácter y retrocede el cursor
                }
            }
        } while (key.Key != ConsoleKey.Enter);

        Console.WriteLine();
        string maskedPassword = MaskPassword(numeroTarjeta);
        
        string hashedPassword = HashPassword(numeroTarjeta);
        

        byte[] claveGenerada = GenerarClaveAleatoria();
        byte[] salGenerada = GenerarSalAleatoria();

        string cadenaCifrada = CifrarAES(numeroTarjeta, claveGenerada, salGenerada);
        

        string cadenaDescifrada = DescifrarAES(cadenaCifrada, claveGenerada, salGenerada);
        

        string hashedPassword2 = HashPassword(cadenaDescifrada);
        

        if (hashedPassword == hashedPassword2)
        {
            Console.WriteLine("los cifrados coinciden, proceso correcto");
            Console.WriteLine("Número enmascarado de tarjeta ingresado: " + maskedPassword);
            Console.WriteLine("Número has256 de tarjeta ingresado: " + hashedPassword);
            Console.WriteLine("Cadena cifrada: " + cadenaCifrada);
            Console.WriteLine("Cadena descifrada: " + cadenaDescifrada);
            Console.WriteLine("Número has256 de cadena descifrada: " + hashedPassword2);
        }

    }


    static string MaskPassword(string password)
    {

        string maskedPart = new string('*', 12);
        return maskedPart + password.Substring(12);

        return password;
    }

    static string HashPassword(string password)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] hashedBytes = sha256.ComputeHash(passwordBytes);
            return Convert.ToBase64String(hashedBytes);
        }
    }

    static string CifrarAES(string cadena, byte[] clave, byte[] iv)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = clave;
            aesAlg.IV = iv;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(cadena);
                    }
                }

                return Convert.ToBase64String(msEncrypt.ToArray());
            }
        }
    }

    static string DescifrarAES(string cadenaCifrada, byte[] clave, byte[] iv)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = clave;
            aesAlg.IV = iv;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(cadenaCifrada)))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }
    }

    static byte[] GenerarClaveAleatoria()
    {
        using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
        {
            byte[] key = new byte[32]; // 256 bits para AES-256
            rngCsp.GetBytes(key);
            return key;
        }
    }

    static byte[] GenerarSalAleatoria()
    {
        using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
        {
            byte[] salt = new byte[16]; // Longitud recomendada para sal
            rngCsp.GetBytes(salt);
            return salt;
        }
    }
}
