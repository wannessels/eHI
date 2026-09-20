using System;
using Xunit;

public sealed class IntegrationFactAttribute : FactAttribute
{
    public IntegrationFactAttribute()
    { if (Environment.GetEnvironmentVariable("EHI_RUN_INTEGRATION") != "1") Skip = "Requires integration fixtures/services; set EHI_RUN_INTEGRATION=1 in a prepared environment."; }
}
public sealed class IntegrationTheoryAttribute : TheoryAttribute
{
    public IntegrationTheoryAttribute()
    { if (Environment.GetEnvironmentVariable("EHI_RUN_INTEGRATION") != "1") Skip = "Requires integration fixtures/services; set EHI_RUN_INTEGRATION=1 in a prepared environment."; }
}
public sealed class HardwareFactAttribute : FactAttribute
{
    public HardwareFactAttribute()
    { if (Environment.GetEnvironmentVariable("EHI_RUN_HARDWARE_TESTS") != "1") Skip = "Requires an attached eID and operator; set EHI_RUN_HARDWARE_TESTS=1 locally."; }
}
