/*
 * This file is part of .Net ETEE for eHealth.
 * Copyright (C) 2014 Egelke
 * 
 * .Net ETEE for eHealth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * .Net ETEE for eHealth  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with .Net ETEE for eHealth.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Egelke.EHealth.Client.Pki;

namespace Egelke.EHealth.Etee.Crypto.Configuration
{
    /// <summary>
    /// Global settings class of the library.
    /// </summary>
    public class Settings
    {
        private static Settings defaultInstance = new Settings();

        /// <summary>
        /// The default instance of the settings class, always use this.
        /// </summary>
        public static Settings Default
        {
            get
            {
                return defaultInstance;
            }
        }

        /// <summary>
        /// The max delay between the time-stamp and signing time.
        /// </summary>
        /// <remarks>
        /// The default value is 5 minutes.
        /// </remarks>
        public TimeSpan TimestampGracePeriod { get; set; }

        /// <summary>
        /// Streams larger than this many bytes spill to temporary files; smaller ones stay in memory.
        /// </summary>
        /// <value>
        /// <para>
        /// Defaults to <see cref="long.MaxValue"/>: nothing spills and no temporary file is created. Set a finite
        /// size at application startup to use temporary files above it, for example
        /// <c>Settings.Default.InMemorySize = 64L * 1024 * 1024;</c> to spill streams above 64 MiB.
        /// </para>
        /// <para>
        /// This is a per-stream threshold, not a cap on total process memory; the metrics
        /// <c>ehealth.spools</c>, <c>ehealth.spool.spills</c> and <c>ehealth.spool.bytes</c> show what happens.
        /// </para>
        /// </value>
        public long InMemorySize { get; set; }

        /// <summary>
        /// Maximum private-key handles opened per signing certificate or WebKey, so concurrent seals and WS-Security requests sign in parallel; handles open on demand.
        /// Defaults to the processor count. Set 1 for keys that cannot be used concurrently, such as smart cards. Same value as <see cref="SigningKeyPool.DefaultLimit"/>.
        /// </summary>
        public int SigningKeyHandles { get => SigningKeyPool.DefaultLimit; set => SigningKeyPool.DefaultLimit = value; }

        /// <summary>
        /// Maximum bytes of freed spool memory kept in the pool for reuse. Defaults to 256 MiB and is read when the pool is first used, so set it at startup.
        /// </summary>
        public long SpoolPoolBytes { get; set; }

        private int maximumNativeMetadataSize = 16 * 1024 * 1024;
        /// <summary>Maximum aggregate encoded metadata decoded per native CMS layer, excluding payloads. Defaults to 16 MiB.</summary>
        public int MaximumNativeMetadataSize
        {
            get => System.Threading.Volatile.Read(ref maximumNativeMetadataSize);
            set { if (value <= 0) throw new ArgumentOutOfRangeException(nameof(value)); System.Threading.Volatile.Write(ref maximumNativeMetadataSize, value); }
        }

        /// <summary>
        /// Number of times the outer signature is retried after a CryptographicException, with a back-off of 10^n ms.
        /// </summary>
        /// <remarks>
        /// Works around eID smart cards that refuse to sign twice in quick succession; defaults to 4 on Windows and 0 elsewhere.
        /// </remarks>
        public int SignRetries { get; set; }

        private volatile bool useNativeCrypto = true;

        /// <summary>
        /// Selects native .NET message cryptography (true, the default) or the streaming
        /// BouncyCastle implementation (false). Factories capture this choice when creating
        /// a sealer, unsealer, verifier or completer; existing instances keep their implementation.
        /// Certificate, revocation and timestamp validation remain shared.
        /// </summary>
        public bool UseNativeCrypto
        {
            get => useNativeCrypto;
            set => useNativeCrypto = value;
        }

        private Settings()
        {
            TimestampGracePeriod = new TimeSpan(0, 5, 0);
            InMemorySize = long.MaxValue;
            SpoolPoolBytes = 256L * 1024 * 1024;
            SignRetries = Environment.OSVersion.Platform == PlatformID.Win32NT ? 4 : 0;
        }
    }
}
