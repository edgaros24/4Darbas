using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;

public class RSADigitalSignature
{
    static void Main()
    {
        // Generate RSA key pair
        using (var rsa = new RSACryptoServiceProvider())
        {
            // Get the private and public keys
            RSAParameters privateKey = rsa.ExportParameters(true);
            RSAParameters publicKey = rsa.ExportParameters(false);

            // Input text
            Console.WriteLine("Enter text");
            string message = Console.ReadLine();

            // Compute the digital signature
            byte[] signature = SignData(Encoding.UTF8.GetBytes(message), privateKey);

            // Convert signature, message, and public key to base64 strings for transmission
            string base64Signature = Convert.ToBase64String(signature);
            string base64Message = Convert.ToBase64String(Encoding.UTF8.GetBytes(message));
            string base64PublicKey = Convert.ToBase64String(Encoding.UTF8.GetBytes(GetPublicKeyString(publicKey)));

            // Connect to the second application
            using (var client = new TcpClient("127.0.0.1", 8080))
            {
                // Get the network stream for sending data
                NetworkStream stream = client.GetStream();

                // Send the message, signature, and public key
                byte[] data = Encoding.UTF8.GetBytes(base64Message + "|" + base64Signature + "|" + base64PublicKey);
                stream.Write(data, 0, data.Length);
            }
        }

        Console.WriteLine("Message, digital signature, and public key sent. Press Enter to exit.");
        Console.ReadLine();
    }

    // Method to compute the digital signature
    static byte[] SignData(byte[] data, RSAParameters privateKey)
    {
        using (var rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportParameters(privateKey);
            return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }

    // Method to get the string representation of the public key
    static string GetPublicKeyString(RSAParameters publicKey)
    {
        StringBuilder sb = new StringBuilder();
        sb.Append(publicKey.Modulus.Length.ToString()).Append(":");
        sb.Append(Convert.ToBase64String(publicKey.Modulus)).Append(":");
        sb.Append(publicKey.Exponent.Length.ToString()).Append(":");
        sb.Append(Convert.ToBase64String(publicKey.Exponent));
        return sb.ToString();
    }
}
