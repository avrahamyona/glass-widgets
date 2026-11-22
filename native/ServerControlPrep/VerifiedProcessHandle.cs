// PREPARATION SOURCE ONLY. Not compiled or run on the user's PC.
// No executable entry point, network, startup edit, elevation or PID-only stop API.
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace GlassWidgets.ServerControlPrep {
 public sealed class ExpectedProcessIdentity {
  public readonly uint Pid;
  public readonly long NativeCreatedFileTimeUtc;
  public readonly string Executable, OwnerSid, LogonSid;
  public ExpectedProcessIdentity(uint pid,long nativeCreatedFileTimeUtc,string executable,string ownerSid,string logonSid) {
   if(pid==0 || nativeCreatedFileTimeUtc<=0 || String.IsNullOrWhiteSpace(executable) || !System.IO.Path.IsPathRooted(executable))throw new ArgumentException("native_identity_required");
   new SecurityIdentifier(ownerSid);new SecurityIdentifier(logonSid);
   if(!logonSid.StartsWith("S-1-5-5-",StringComparison.Ordinal))throw new ArgumentException("logon_sid_required");
   Pid=pid;NativeCreatedFileTimeUtc=nativeCreatedFileTimeUtc;Executable=executable;OwnerSid=ownerSid;LogonSid=logonSid;
  }
 }
 public sealed class HandleInspection {
  public readonly ExpectedProcessIdentity Identity;
  public readonly bool Exited, Verified;
  internal HandleInspection(ExpectedProcessIdentity identity,bool exited){Identity=identity;Exited=exited;Verified=true;}
 }
 public sealed class VerifiedProcessHandle : IDisposable {
  const uint QueryLimited=0x1000, Synchronize=0x100000, Terminate=1, Timeout=258;
  readonly object gate=new object();
  readonly ExpectedProcessIdentity expected;
  readonly bool stopCapable;
  IntPtr processHandle;
  bool disposed,terminationRequested;

  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint rights,bool inherit,uint pid);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetProcessId(IntPtr handle);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr handle,out long created,out long exit,out long kernel,out long user);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr handle,uint flags,StringBuilder buffer,ref uint length);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr handle,uint exitCode);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr handle,uint access,out IntPtr token);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int info,IntPtr buffer,uint size,out uint returned);
  [StructLayout(LayoutKind.Sequential)] struct SidAndAttributes { public IntPtr Sid;public uint Attributes; }
  [StructLayout(LayoutKind.Sequential)] struct GroupsHeader { public uint Count;public SidAndAttributes First; }

  VerifiedProcessHandle(ExpectedProcessIdentity identity,bool mayStop) {
   if(identity==null)throw new ArgumentNullException("identity");expected=identity;stopCapable=mayStop;
   processHandle=OpenProcess(QueryLimited|Synchronize|(mayStop?Terminate:0u),false,identity.Pid);
   if(processHandle==IntPtr.Zero)throw new InvalidOperationException("open_process_failed");
   try{var state=InspectLocked();if(state.Exited)throw new InvalidOperationException("process_already_exited");}
   catch{CloseHandle(processHandle);processHandle=IntPtr.Zero;disposed=true;throw;}
  }
  // These factories are capabilities, not approval. The caller still owes reviewed scope.
  public static VerifiedProcessHandle OpenForObservation(ExpectedProcessIdentity identity){return new VerifiedProcessHandle(identity,false);}
  public static VerifiedProcessHandle OpenForStop(ExpectedProcessIdentity identity){return new VerifiedProcessHandle(identity,true);}
  public bool StopCapable { get {return stopCapable;} }
  void EnsureOpen(){if(disposed||processHandle==IntPtr.Zero)throw new ObjectDisposedException("VerifiedProcessHandle");}
  bool HasExitedLocked(){
   uint result=WaitForSingleObject(processHandle,0);
   if(result==0)return true;if(result==Timeout)return false;
   throw new InvalidOperationException("process_wait_failed");
  }
  static string ReadLogonSid(IntPtr token){
   uint needed;GetTokenInformation(token,2,IntPtr.Zero,0,out needed);
   if(needed<8||needed>1048576)throw new InvalidOperationException("token_groups_size_invalid");
   IntPtr buffer=Marshal.AllocHGlobal((int)needed);
   try {
    uint returned;if(!GetTokenInformation(token,2,buffer,needed,out returned))throw new InvalidOperationException("token_groups_failed");
    int count=Marshal.ReadInt32(buffer),offset=(int)Marshal.OffsetOf(typeof(GroupsHeader),"First"),stride=Marshal.SizeOf(typeof(SidAndAttributes));
    if(count<1||count>4096||offset+(long)count*stride>returned)throw new InvalidOperationException("token_groups_bounds_invalid");
    string found=null;
    for(int i=0;i<count;i++){
     var row=(SidAndAttributes)Marshal.PtrToStructure(IntPtr.Add(buffer,offset+i*stride),typeof(SidAndAttributes));
     if((row.Attributes&0xC0000000)==0xC0000000){if(found!=null)throw new InvalidOperationException("multiple_logon_sids");found=new SecurityIdentifier(row.Sid).Value;}
    }
    if(found==null)throw new InvalidOperationException("logon_sid_missing");return found;
   }finally{Marshal.FreeHGlobal(buffer);}
  }
  HandleInspection InspectLocked(){
   EnsureOpen();
   long created,exit,kernel,user;
   if(GetProcessId(processHandle)!=expected.Pid||!GetProcessTimes(processHandle,out created,out exit,out kernel,out user)||created!=expected.NativeCreatedFileTimeUtc)throw new InvalidOperationException("native_process_identity_changed");
   // After exit, the held kernel object and exact creation ticks retain the binding.
   // Token queries can no longer succeed then, so do not reopen by PID to query them.
   if(HasExitedLocked())return new HandleInspection(expected,true);
   var image=new StringBuilder(32768);uint size=32768;
   if(!QueryFullProcessImageName(processHandle,0,image,ref size)||!String.Equals(image.ToString(),expected.Executable,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("process_image_changed");
   IntPtr token=IntPtr.Zero;
   try {
    if(!OpenProcessToken(processHandle,8,out token))throw new InvalidOperationException("process_token_query_failed");
    string owner;using(var wi=new WindowsIdentity(token)){owner=wi.User.Value;}
    if(!String.Equals(owner,expected.OwnerSid,StringComparison.Ordinal)||!String.Equals(ReadLogonSid(token),expected.LogonSid,StringComparison.Ordinal))throw new InvalidOperationException("process_owner_or_logon_changed");
   }finally{if(token!=IntPtr.Zero&&!CloseHandle(token))throw new InvalidOperationException("token_close_failed");}
   return new HandleInspection(expected,HasExitedLocked());
  }
  public HandleInspection Inspect(CancellationToken cancellation){lock(gate){cancellation.ThrowIfCancellationRequested();return InspectLocked();}}
  public void RequestTermination(CancellationToken cancellation){
   lock(gate){
    EnsureOpen();if(!stopCapable)throw new InvalidOperationException("observation_handle_cannot_stop");
    if(terminationRequested)throw new InvalidOperationException("termination_already_requested");
    cancellation.ThrowIfCancellationRequested();if(InspectLocked().Exited)throw new InvalidOperationException("process_exited_before_request");
    cancellation.ThrowIfCancellationRequested();
    // A request is never exit proof. No retry follows a failed/uncertain request.
    terminationRequested=true;
    if(!TerminateProcess(processHandle,0))throw new InvalidOperationException("termination_request_failed");
   }
  }
  public bool WaitForExit(int deadlineMilliseconds,CancellationToken cancellation){
   if(deadlineMilliseconds<1||deadlineMilliseconds>30000)throw new ArgumentOutOfRangeException("deadlineMilliseconds");
   var clock=Stopwatch.StartNew();
   // Keep this lock throughout wait slices: Dispose cannot close a waited-on handle.
   lock(gate){
    EnsureOpen();while(true){
     cancellation.ThrowIfCancellationRequested();
     int remaining=deadlineMilliseconds-(int)clock.ElapsedMilliseconds;
     if(remaining<=0)return HasExitedLocked();
     uint result=WaitForSingleObject(processHandle,(uint)Math.Min(50,remaining));
     if(result==0)return true;if(result!=Timeout)throw new InvalidOperationException("process_wait_failed");
    }
   }
  }
  public void Dispose(){
   lock(gate){if(disposed)return;disposed=true;var h=processHandle;processHandle=IntPtr.Zero;
    if(h!=IntPtr.Zero&&!CloseHandle(h))throw new InvalidOperationException("process_handle_close_failed");
   }
   GC.SuppressFinalize(this);
  }
  ~VerifiedProcessHandle(){lock(gate){if(processHandle!=IntPtr.Zero){CloseHandle(processHandle);processHandle=IntPtr.Zero;}disposed=true;}}
 }
}
