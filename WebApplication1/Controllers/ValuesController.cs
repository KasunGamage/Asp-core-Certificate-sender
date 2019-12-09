using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Mvc;

namespace WebApplication1.Controllers
{
    [Route("api/CertificateSender")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        // GET api/values
        [HttpGet]
        public ActionResult<IEnumerable<string>> Get()
        {
            var result = sendGetRequest();
            return new string[] { result };
        }

        public string sendGetRequest()
        {
            var response = "";
            string BaseUrl = "YOUR_SERVER_URL";
            string cerPath = "public.crt.pem file path";
            string cerKey = "private.key.pem file path";
            string cerStream;
            string keyStream;

            using (TextReader tr = new StreamReader(cerPath))
            {
                cerStream = tr.ReadToEnd();
            }

            using (TextReader tr = new StreamReader(cerKey))
            {
                keyStream = tr.ReadToEnd();
            }

            byte[] certBuffer = GetBytesFromPEM(cerStream, "CERTIFICATE");
            byte[] keyBuffer = GetBytesFromPEM(keyStream, "PRIVATE KEY");

            X509Certificate2 certificate = new X509Certificate2(certBuffer);

            RSA prov = DecodeRSAPkcs8(keyBuffer);
            X509Certificate2 certWithPrivateKey = ExportCertificate(certificate, prov);

            string requestUri = BaseUrl + "/fhir/PractitionerRole?active=true&practitioner.family=Kidman&_include=PractitionerRole:practitioner&_include=PractitionerRole:location&_include=PractitionerRole:organization&_include=PractitionerRole:endpoint&_include=PractitionerRole:service";

            HttpWebRequest tRequest = (HttpWebRequest)WebRequest.Create(requestUri);

            tRequest.ClientCertificates.Add(certWithPrivateKey);
            tRequest.Method = "GET";
            tRequest.ContentType = "application/json";

            HttpWebResponse tResponse2 = (HttpWebResponse)tRequest.GetResponse();

            using (HttpWebResponse tResponse = (HttpWebResponse)tRequest.GetResponse())
            {
                using (Stream dataStreamResponse = tResponse.GetResponseStream())
                {
                    using (StreamReader tReader = new StreamReader(dataStreamResponse))
                    {
                        var sResponseFromServer = tReader.ReadToEnd();
                        response = sResponseFromServer;
                    }
                }
            }

            return response;
        }

        private X509Certificate2 ExportCertificate(X509Certificate2 certificate, RSA prov)
        {
            using (X509Certificate2 certWithPrivateKey = certificate.CopyWithPrivateKey(prov))
            {
                return new X509Certificate2(certWithPrivateKey.Export(X509ContentType.Pkcs12));
            }

        }

        byte[] GetBytesFromPEM(string pemString, string section)
        {
            //var header = String.Format("-----BEGIN {0}-----", section);
            //var footer = String.Format("-----END {0}-----", section);

            //var start = pemString.IndexOf(header, StringComparison.Ordinal);
            //if (start < 0)
            //    return null;

            //start += header.Length;
            //var end = pemString.IndexOf(footer, start, StringComparison.Ordinal) - start;

            //if (end < 0)
            //    return null;

            //return Convert.FromBase64String(pemString.Substring(start, end));
            string header; string footer;

            switch (section)
            {
                case "CERTIFICATE":
                    header = "-----BEGIN CERTIFICATE-----";
                    footer = "-----END CERTIFICATE-----";
                    break;
                case "PRIVATE KEY":
                    header = "-----BEGIN PRIVATE KEY-----";
                    footer = "-----END PRIVATE KEY-----";
                    break;
                default:
                    return null;
            }

            int start = pemString.IndexOf(header) + header.Length;
            int end = pemString.IndexOf(footer, start) - start;
            return Convert.FromBase64String(pemString.Substring(start, end));

        }

        private static readonly byte[] s_derIntegerZero = { 0x02, 0x01, 0x00 };

        private static readonly byte[] s_rsaAlgorithmId =
        {
         0x30, 0x0D,
         0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
         0x05, 0x00,
        };

        private static int ReadLength(byte[] data, ref int offset)
        {
            byte lengthOrLengthLength = data[offset++];

            if (lengthOrLengthLength < 0x80)
            {
                return lengthOrLengthLength;
            }

            int lengthLength = lengthOrLengthLength & 0x7F;
            int length = 0;

            for (int i = 0; i < lengthLength; i++)
            {
                if (length > ushort.MaxValue)
                {
                    throw new InvalidOperationException("This seems way too big.");
                }

                length <<= 8;
                length |= data[offset++];
            }

            return length;
        }

        private static byte[] ReadUnsignedInteger(byte[] data, ref int offset, int targetSize = 0)
        {
            if (data[offset++] != 0x02)
            {
                throw new InvalidOperationException("Invalid encoding");
            }

            int length = ReadLength(data, ref offset);

            // Encoding rules say 0 is encoded as the one byte value 0x00.
            // Since we expect unsigned, throw if the high bit is set.
            if (length < 1 || data[offset] >= 0x80)
            {
                throw new InvalidOperationException("Invalid encoding");
            }

            byte[] ret;

            if (length == 1)
            {
                ret = new byte[length];
                ret[0] = data[offset++];
                return ret;
            }

            if (data[offset] == 0)
            {
                offset++;
                length--;
            }

            if (targetSize != 0)
            {
                if (length > targetSize)
                {
                    throw new InvalidOperationException("Bad key parameters");
                }

                ret = new byte[targetSize];
            }
            else
            {
                ret = new byte[length];
            }

            Buffer.BlockCopy(data, offset, ret, ret.Length - length, length);
            offset += length;
            return ret;
        }

        private static void EatFullPayloadTag(byte[] data, ref int offset, byte tagValue)
        {
            if (data[offset++] != tagValue)
            {
                throw new InvalidOperationException("Invalid encoding");
            }

            int length = ReadLength(data, ref offset);

            if (data.Length - offset != length)
            {
                throw new InvalidOperationException("Data does not represent precisely one value");
            }
        }

        private static void EatMatch(byte[] data, ref int offset, byte[] toMatch)
        {
            if (data.Length - offset > toMatch.Length)
            {
                if (data.Skip(offset).Take(toMatch.Length).SequenceEqual(toMatch))
                {
                    offset += toMatch.Length;
                    return;
                }
            }

            throw new InvalidOperationException("Bad data.");
        }

        private static RSA DecodeRSAPkcs8(byte[] pkcs8Bytes)
        {
            int offset = 0;

            // PrivateKeyInfo SEQUENCE
            EatFullPayloadTag(pkcs8Bytes, ref offset, 0x30);
            // PKCS#8 PrivateKeyInfo.version == 0
            EatMatch(pkcs8Bytes, ref offset, s_derIntegerZero);
            // rsaEncryption AlgorithmIdentifier value
            EatMatch(pkcs8Bytes, ref offset, s_rsaAlgorithmId);
            // PrivateKeyInfo.privateKey OCTET STRING
            EatFullPayloadTag(pkcs8Bytes, ref offset, 0x04);
            // RSAPrivateKey SEQUENCE
            EatFullPayloadTag(pkcs8Bytes, ref offset, 0x30);
            // RSAPrivateKey.version == 0
            EatMatch(pkcs8Bytes, ref offset, s_derIntegerZero);

            RSAParameters rsaParameters = new RSAParameters();
            rsaParameters.Modulus = ReadUnsignedInteger(pkcs8Bytes, ref offset);
            rsaParameters.Exponent = ReadUnsignedInteger(pkcs8Bytes, ref offset);
            rsaParameters.D = ReadUnsignedInteger(pkcs8Bytes, ref offset, rsaParameters.Modulus.Length);
            int halfModulus = (rsaParameters.Modulus.Length + 1) / 2;
            rsaParameters.P = ReadUnsignedInteger(pkcs8Bytes, ref offset, halfModulus);
            rsaParameters.Q = ReadUnsignedInteger(pkcs8Bytes, ref offset, halfModulus);
            rsaParameters.DP = ReadUnsignedInteger(pkcs8Bytes, ref offset, halfModulus);
            rsaParameters.DQ = ReadUnsignedInteger(pkcs8Bytes, ref offset, halfModulus);
            rsaParameters.InverseQ = ReadUnsignedInteger(pkcs8Bytes, ref offset, halfModulus);

            if (offset != pkcs8Bytes.Length)
            {
                throw new InvalidOperationException("Something didn't add up");
            }

            RSA rsa = RSA.Create();
            rsa.ImportParameters(rsaParameters);
            return rsa;
        }

    }
}
