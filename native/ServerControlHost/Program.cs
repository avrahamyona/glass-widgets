// Local integration candidate. Private stdio only. No listener, installation or elevation.
// The process owns handles, not approval. Its parent owes the reviewed server plan.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Security.Principal;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using GlassWidgets.ServerControlPrep;

internal static class Program {
 const int MaxPacket=65536, MaxHandles=32, MaxRequests=32;
 static readonly object OutputGate=new object();
 static readonly ConcurrentDictionary<string,Entry> Handles=new ConcurrentDictionary<string,Entry>();
 static readonly ConcurrentDictionary<string,CancellationTokenSource> Requests=new ConcurrentDictionary<string,CancellationTokenSource>();
 static readonly ConcurrentDictionary<string,Task> Workers=new ConcurrentDictionary<string,Task>();
 static readonly SemaphoreSlim HandleSlots=new SemaphoreSlim(MaxHandles,MaxHandles);
 static readonly CancellationTokenSource Shutdown=new CancellationTokenSource();
 static readonly Regex RequestId=new Regex("^[1-9][0-9]{0,19}$",RegexOptions.CultureInvariant);
 sealed class Entry {
  internal readonly VerifiedProcessHandle Handle;
  internal Entry(VerifiedProcessHandle handle){Handle=handle;}
 }
 sealed class Request {
  public string Id {get;set;}
  public string Op {get;set;}
  public string Handle {get;set;}
  public Identity Identity {get;set;}
  public int WaitMs {get;set;}
  public int Pid {get;set;}
  public string LogonSid {get;set;}
 }
 sealed class Identity {
  public uint Pid {get;set;}
  public string NativeCreatedFileTimeUtc {get;set;}
  public string Executable {get;set;}
  public string OwnerSid {get;set;}
  public string LogonSid {get;set;}
 }
 static readonly JsonSerializerOptions Json=new JsonSerializerOptions {PropertyNameCaseInsensitive=false,PropertyNamingPolicy=JsonNamingPolicy.CamelCase,MaxDepth=8};
 static object WireIdentity(ExpectedProcessIdentity value) {
  return new {pid=value.Pid,nativeCreatedFileTimeUtc=value.NativeCreatedFileTimeUtc.ToString(CultureInfo.InvariantCulture),executable=value.Executable,ownerSid=value.OwnerSid,logonSid=value.LogonSid};
 }
 static ExpectedProcessIdentity ParseIdentity(Identity value) {
  long ticks;
  if(value==null || value.Executable==null || value.Executable.Length>32768 || value.OwnerSid==null || value.OwnerSid.Length>184 || value.LogonSid==null || value.LogonSid.Length>184 || value.NativeCreatedFileTimeUtc==null || !Regex.IsMatch(value.NativeCreatedFileTimeUtc,"^[1-9][0-9]{0,18}$",RegexOptions.CultureInvariant) || !long.TryParse(value.NativeCreatedFileTimeUtc,NumberStyles.None,CultureInfo.InvariantCulture,out ticks))throw new InvalidOperationException("native_identity_required");
  return new ExpectedProcessIdentity(value.Pid,ticks,value.Executable,value.OwnerSid,value.LogonSid);
 }
 static Entry Find(string key) {
  Entry entry;
  if(key==null || !Regex.IsMatch(key,"^[a-f0-9]{32}$",RegexOptions.CultureInvariant) || !Handles.TryGetValue(key,out entry))throw new InvalidOperationException("unknown_handle");
  return entry;
 }
 static void Write(object message) {
  lock(OutputGate){Console.Out.WriteLine(JsonSerializer.Serialize(message,Json));Console.Out.Flush();}
 }
 static string ReadPacket(TextReader reader) {
  var text=new StringBuilder();
  while(true){int c=reader.Read();if(c<0){if(text.Length!=0)throw new InvalidOperationException("partial_packet");return null;}if(c=='\n')return text.ToString();if(c=='\r')throw new InvalidOperationException("invalid_packet_ending");if(text.Length>=MaxPacket)throw new InvalidOperationException("packet_too_large");text.Append((char)c);}
 }
 static object Execute(Request request,CancellationToken cancellation) {
  cancellation.ThrowIfCancellationRequested();
  switch(request.Op){
   case "describe":return new {protocol=1,transport="private-stdio",nativePlatform="win32",identityTime="decimal-filetime-string"};
   case "capture-observation": {
    if(request.Pid<1 || request.LogonSid==null || !Regex.IsMatch(request.LogonSid,"^S-1-5-5-[0-9]+-[0-9]+$",RegexOptions.CultureInvariant))throw new InvalidOperationException("observation_context_required");
    using(var process=Process.GetProcessById(request.Pid)){
     // Keep Process.SafeHandle alive while deriving the expectation, then let the
     // existing native library verify it against a separate held observation handle.
     var held=process.SafeHandle;
     if(held.IsInvalid || process.HasExited)throw new InvalidOperationException("process_already_exited");
     long ticks=process.StartTime.ToUniversalTime().ToFileTimeUtc();
     string executable=process.MainModule.FileName;
     string owner;using(var self=WindowsIdentity.GetCurrent()){owner=self.User.Value;}
     var expected=new ExpectedProcessIdentity((uint)request.Pid,ticks,executable,owner,request.LogonSid);
     using(var observation=VerifiedProcessHandle.OpenForObservation(expected)){
      var inspected=observation.Inspect(cancellation);
      if(inspected.Exited)throw new InvalidOperationException("process_already_exited");
      return new {verified=true,identity=WireIdentity(inspected.Identity),createdAt=DateTime.FromFileTimeUtc(ticks).ToString("o",CultureInfo.InvariantCulture),scope="observation-only-not-a-stop-plan"};
     }
    }
   }
   case "open-observe":case "open-stop": {
    var expected=ParseIdentity(request.Identity);
    if(!HandleSlots.Wait(0))throw new InvalidOperationException("handle_limit");
    VerifiedProcessHandle handle=null;bool registered=false;
    try {
     cancellation.ThrowIfCancellationRequested();
     handle=request.Op=="open-stop"?VerifiedProcessHandle.OpenForStop(expected):VerifiedProcessHandle.OpenForObservation(expected);
     cancellation.ThrowIfCancellationRequested();
     string key=Guid.NewGuid().ToString("N");
     if(!Handles.TryAdd(key,new Entry(handle)))throw new InvalidOperationException("handle_registration_failed");
     registered=true;
     return new {handle=key,stopCapable=handle.StopCapable,identity=WireIdentity(expected)};
    } finally {if(!registered){try{if(handle!=null)handle.Dispose();}finally{HandleSlots.Release();}}}
   }
   case "inspect": {
    var value=Find(request.Handle).Handle.Inspect(cancellation);
    return new {verified=value.Verified,exited=value.Exited,identity=WireIdentity(value.Identity)};
   }
   case "stop":Find(request.Handle).Handle.RequestTermination(cancellation);return new {requestAccepted=true};
   case "wait": {
    var entry=Find(request.Handle);
    bool exited=entry.Handle.WaitForExit(request.WaitMs,cancellation);
    // A timeout is not a verified exit. Keep the handle for cleanup, never reopen by PID.
    return new {exited,verified=exited};
   }
   case "close": {
    Entry entry;
    if(request.Handle==null || !Handles.TryRemove(request.Handle,out entry))throw new InvalidOperationException("unknown_handle");
    try{entry.Handle.Dispose();return new {closed=true};}finally{HandleSlots.Release();}
   }
   default:throw new InvalidOperationException("unknown_operation");
  }
 }
 static string ErrorCode(Exception error) {
  if(error is OperationCanceledException)return "operation_aborted";
  // Never return exception text containing paths, raw metadata, command lines or a stack.
  if(error is InvalidOperationException && Regex.IsMatch(error.Message,"^[a-z_]{1,80}$",RegexOptions.CultureInvariant))return error.Message;
  return "native_operation_failed";
 }
 static void Accept(string line) {
  using(var document=JsonDocument.Parse(line,new JsonDocumentOptions {MaxDepth=8})){
   var root=document.RootElement;
   JsonElement target;
   if(root.ValueKind==JsonValueKind.Object && root.TryGetProperty("cancel",out target)){
    if(root.EnumerateObject().Count()!=1 || target.ValueKind!=JsonValueKind.String || !RequestId.IsMatch(target.GetString()??""))throw new InvalidOperationException("invalid_cancel_packet");
    CancellationTokenSource pending;
    if(Requests.TryGetValue(target.GetString(),out pending)){try{pending.Cancel();}catch(ObjectDisposedException){}}
    return;
   }
  }
  var request=JsonSerializer.Deserialize<Request>(line,Json);
  if(request==null || !RequestId.IsMatch(request.Id??"") || request.Op==null || request.Op.Length>32)throw new InvalidOperationException("invalid_request");
  if(Requests.Count>=MaxRequests){Write(new {id=request.Id,ok=false,error="request_limit"});return;}
  var source=CancellationTokenSource.CreateLinkedTokenSource(Shutdown.Token);
  if(!Requests.TryAdd(request.Id,source)){source.Dispose();throw new InvalidOperationException("duplicate_request");}
  // Waiting must not block the reader: cancellation packets keep being read.
  var worker=Task.Run(()=>{
   try {var result=Execute(request,source.Token);Write(new {id=request.Id,ok=true,result});}
   catch(Exception error){Write(new {id=request.Id,ok=false,error=ErrorCode(error)});}
   finally{CancellationTokenSource removed;Requests.TryRemove(request.Id,out removed);source.Dispose();}
  });
  if(!Workers.TryAdd(request.Id,worker))throw new InvalidOperationException("worker_registration_failed");
  _=worker.ContinueWith(completed=>{Task removed;Workers.TryRemove(request.Id,out removed);},TaskScheduler.Default);
 }
 static async Task<int> Main(string[] args) {
  Console.OutputEncoding=new UTF8Encoding(false);
  if(args.Length==1 && args[0]=="--describe"){
   Write(new {protocol=1,transport="private-stdio",nativePlatform="win32",operations=new[]{"capture-observation","open-observe","open-stop","inspect","stop","wait","close"},timeEncoding="decimal-filetime-string",nativeExecutionTestedHere=false});return 0;
  }
  if(args.Length!=0 || !OperatingSystem.IsWindows()){Console.Error.WriteLine("windows_native_host_required");return 2;}
  int exit=0;
  try {
   using(var reader=new StreamReader(Console.OpenStandardInput(),new UTF8Encoding(false,true),false,4096,false)){
    string line;while((line=ReadPacket(reader))!=null){if(line.Length==0)throw new InvalidOperationException("empty_packet");Accept(line);}
   }
  }catch{exit=3;Console.Error.WriteLine("native_control_protocol_failed");}
  finally{
   Shutdown.Cancel();
   try{await Task.WhenAll(Workers.Values.ToArray());}catch{exit=4;}
   foreach(var row in Handles.ToArray()){
    Entry entry;if(Handles.TryRemove(row.Key,out entry)){try{entry.Handle.Dispose();}catch{exit=5;}finally{HandleSlots.Release();}}
   }
  }
  return exit;
 }
}
