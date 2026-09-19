using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>
    /// Time-mark provider that can be awaited; the library prefers this over <see cref="ITimemarkProvider"/> when both are implemented.
    /// </summary>
    public interface ITimemarkProviderAsync : ITimemarkProvider
    {
        /// <summary>
        /// Get the time-mark of a message.
        /// </summary>
        /// <seealso cref="ITimemarkProvider.GetTimemark(X509Certificate2, DateTime, byte[])"/>
        /// <param name="sender">The sender of the message</param>
        /// <param name="signingTime">The signing time as indicated in the message</param>
        /// <param name="signatureValue">The signature value of the message</param>
        /// <returns>The trusted time the message was received</returns>
        Task<DateTime> GetTimemarkAsync(X509Certificate2 sender, DateTime signingTime, byte[] signatureValue);
    }
}
