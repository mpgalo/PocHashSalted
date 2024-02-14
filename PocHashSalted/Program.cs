using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Security.Cryptography;

namespace PocHashSalted
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.Write("Enter a password: ");
            string password = Console.ReadLine();

            // Gera um salt de 128 bits (16 bytes)           
            byte[] salt = new Byte[128 / 8];

            //RNGCryptoServiceProvider é uma implementação da geração de um número randomico
            //byte[] salt = RandomNumberGenerator.GetBytes(128 / 8); --> Apenas .NET 5.0 ou superior
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(salt);
            
            //O Salt em formato string deve ser armazenado no banco de dados na tabela de usuário
            Console.WriteLine($"Salt: {Convert.ToBase64String(salt)}");

            string hashed = CreatePassword(Convert.ToBase64String(salt), password);

            Console.WriteLine($"Hashed: {hashed}");

            Console.Write("Verify a password: ");
            string passwordField = Console.ReadLine();

            //O salt deve vir do banco de dados ao fazer o login
            Console.WriteLine(VerifyPassword(Convert.ToBase64String(salt), passwordField, hashed));
        }

        static string CreatePassword(string salt, string password)
        {
            // Deriva uma chave de 256 bits (usando HMACSHA256 com 100,000 iterações)
            return Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password!,
                salt: Convert.FromBase64String(salt),
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 256 / 8));
        }

        static bool VerifyPassword(string salt, string passwordField, string passwordDataBase)
        {
            //A comparação ocorre através da criptografia da senha preenchida no campo e a senha encriptada armazenada no banco de dados
            return CreatePassword(salt, passwordField) == passwordDataBase;
        }
    }
}
