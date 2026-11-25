namespace ProxyTunnelPrototype;

public enum NetworkPhase { Off, WaitingForNetwork, Connecting, Connected, Degraded, Checking, Reconnecting, Stopping, Blocked, Failed }
public sealed class RetrySchedule
{
    public int Failures { get; private set; }
    public TimeSpan Delay=>TimeSpan.FromSeconds(Math.Min(60,3*Math.Pow(2,Math.Min(Math.Max(0,Failures-1),5))));
    public void Failed()=>Failures++;
    public void Reset()=>Failures=0;
}
public sealed class HealthPolicy
{
    public int ConsecutiveFailures { get; private set; }
    public bool NeedsRestart(bool processAlive,bool probeSucceeded)
    {
        if(!processAlive) return true;
        if(probeSucceeded) { ConsecutiveFailures=0; return false; }
        return ++ConsecutiveFailures>=2;
    }
    public void Reset()=>ConsecutiveFailures=0;
}
public sealed class TunnelSafetyException : Exception { public TunnelSafetyException(string message):base(message){} }
