using System.Diagnostics;
using System.Net;
using System.Net.Http;

namespace ProxyTunnelPrototype;

public sealed record ExitResult(string Ip,long Milliseconds,string Source,bool UsedFallback);
public static class ExitProber
{
    public static readonly string[] Endpoints=["https://api.ipify.org","https://www.cloudflare.com/cdn-cgi/trace","https://checkip.amazonaws.com/"];
    public static async Task<ExitResult> Probe(HttpClient http,string expected,CancellationToken token,TimeSpan? attemptTimeout=null)
    {
        var failures=new List<string>();
        for(int i=0;i<Endpoints.Length;i++)
        {
            token.ThrowIfCancellationRequested();
            using var attempt=CancellationTokenSource.CreateLinkedTokenSource(token); attempt.CancelAfter(attemptTimeout??TimeSpan.FromSeconds(8));
            try
            {
                var watch=Stopwatch.StartNew();
                using var response=await http.GetAsync(Endpoints[i],attempt.Token); response.EnsureSuccessStatusCode();
                var body=(await response.Content.ReadAsStringAsync(attempt.Token)).Trim();
                var ip=body.Split('\n').FirstOrDefault(l=>l.StartsWith("ip="))?[3..].Trim()??body;
                if(!IPAddress.TryParse(ip,out _)) throw new HttpRequestException("Ответ не содержит IP.");
                if(ip!=expected) throw new TunnelSafetyException("Выходной IP "+ip+" не совпадает с VPS "+expected+".");
                return new(ip,watch.ElapsedMilliseconds,new Uri(Endpoints[i]).Host,i>0);
            }
            catch(TunnelSafetyException) { throw; }
            catch(Exception ex) when(ex is HttpRequestException or OperationCanceledException)
            {
                token.ThrowIfCancellationRequested(); failures.Add(new Uri(Endpoints[i]).Host);
            }
        }
        throw new HttpRequestException("Не ответили независимые проверки выхода: "+string.Join(", ",failures));
    }
}

