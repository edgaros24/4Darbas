using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;

public class RSADigitalSignatureValidation
{
    static void Main()
    {
        // Start listening on port 8080
        TcpListener server = new TcpListener(IPAddress.Any, 8080);
        server.Start();

        Console.WriteLine("Waiting for connection...");

        // Accept incoming connection
        using (var client = server.AcceptTcpClient())
        {
            Console.WriteLine("Connected!");

            // Get the network stream for receiving data
            NetworkStream stream = client.GetStream();

            // Receive the message, signature, and public key
            byte[] data = new byte[4096];
            int bytesRead = stream.Read(data, 0, data.Length);
            string receivedData = Encoding.UTF8.GetString(data, 0, bytesRead);

            // Split the received data into message, signature, and public key
            string[] parts = receivedData.Split('|');
            string base64Message = parts[0];
            string base64Signature = parts[1];
            string base64PublicKey = parts[2];

            // Convert base64 strings back to byte arrays
            byte[] messageBytes = Convert.FromBase64String(base64Message);
            byte[] signature = Convert.FromBase64String(base64Signature);
            byte[] publicKeyBytes = Convert.FromBase64String(base64PublicKey);

            // Import the public key
            RSAParameters publicKey = new RSAParameters
            {
                Modulus = publicKeyBytes,
                Exponent = new byte[] { 1, 0, 1 } // Assuming a fixed exponent value of [1, 0, 1]
            };

            // Verify the digital signature
            bool isSignatureValid = VerifyData(messageBytes, signature, publicKey);

            if (isSignatureValid)
            {
                Console.WriteLine("Digital signature is valid.");
            }
            else
            {
                Console.WriteLine("Digital signature is not valid.");
            }
        }

        // Stop listening
        server.Stop();

        Console.WriteLine("Press Enter to exit.");
        Console.ReadLine();
    }

    // Method to verify the digital signature
    static bool VerifyData(byte[] data, byte[] signature, RSAParameters publicKey)
    {
        using (var rsa = RSA.Create())
        {
            rsa.ImportParameters(publicKey);
            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }
}
