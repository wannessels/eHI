namespace Egelke.EHealth.Etee.Crypto.Store
{
    /// <summary>
    /// Result of an awaitable time-mark authority operation, pairing the value with its time-mark key.
    /// </summary>
    /// <typeparam name="T">Type of the operation result</typeparam>
    public sealed class TimemarkedResult<T>
    {
        internal TimemarkedResult(T value, TimemarkKey timemarkKey)
        {
            Value = value;
            TimemarkKey = timemarkKey;
        }

        /// <summary>
        /// The operation result.
        /// </summary>
        public T Value { get; }

        /// <summary>
        /// The time-mark key to be linked to the message.
        /// </summary>
        public TimemarkKey TimemarkKey { get; }
    }
}
