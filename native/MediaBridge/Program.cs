using System.Text.Json;
using Windows.Media.Control;
using Windows.Storage.Streams;

// Original, out-of-process bridge. No Powershell reflection or temp command files.
Console.OutputEncoding = System.Text.Encoding.UTF8;
var commands = System.Threading.Channels.Channel.CreateUnbounded<string>();
_ = Task.Run(async () => { string? line; while ((line = await Console.In.ReadLineAsync()) != null) await commands.Writer.WriteAsync(line.Trim()); });
void Emit(object item) { Console.WriteLine(JsonSerializer.Serialize(item)); Console.Out.Flush(); }
GlobalSystemMediaTransportControlsSessionManager manager;
try { manager = await GlobalSystemMediaTransportControlsSessionManager.RequestAsync(); }
catch (Exception e) { Emit(new { none = true, err = "Windows media: " + e.Message }); return; }
string lastKey = "", artwork = "", commandError = "";
DateTime artChecked = DateTime.MinValue;
while (true) {
 try {
  var session = manager.GetCurrentSession();
  var sessions = manager.GetSessions();
  // A stale current session must not hide the active music player.
  if (session == null || session.GetPlaybackInfo().PlaybackStatus != GlobalSystemMediaTransportControlsSessionPlaybackStatus.Playing)
   session = sessions.FirstOrDefault(x => x.GetPlaybackInfo().PlaybackStatus == GlobalSystemMediaTransportControlsSessionPlaybackStatus.Playing) ?? session ?? sessions.FirstOrDefault();
  while (commands.Reader.TryRead(out var cmd)) {
   if (session == null) { commandError = "אין נגן שדיווח ל-Windows"; continue; }
   try {
    bool accepted = cmd switch {
     "toggle" => await session.TryTogglePlayPauseAsync(), "pause" => await session.TryPauseAsync(),
     "play" => await session.TryPlayAsync(), "next" => await session.TrySkipNextAsync(),
     "prev" => await session.TrySkipPreviousAsync(), _ => false
    };
    commandError = accepted ? "" : "הנגן לא אישר את הפעולה";
   } catch (Exception e) { commandError = e.Message; }
  }
  if (session == null) Emit(new { none = true, commandError });
  else {
   var props = await session.TryGetMediaPropertiesAsync(); var pb = session.GetPlaybackInfo(); var tl = session.GetTimelineProperties();
   var key = session.SourceAppUserModelId + "|" + props.Title + "|" + props.Artist + "|" + props.AlbumTitle;
   if (key != lastKey) { artwork = ""; lastKey = key; artChecked = DateTime.MinValue; }
   // Some players publish their cover after the title. Retry instead of caching an empty cover forever.
   if (artwork.Length == 0 && DateTime.UtcNow - artChecked > TimeSpan.FromSeconds(3)) {
    artChecked = DateTime.UtcNow;
    try {
     if (props.Thumbnail != null) {
      using var stream = await props.Thumbnail.OpenReadAsync();
      if (stream.Size > 0 && stream.Size < 8 * 1024 * 1024) {
       using var reader = new DataReader(stream.GetInputStreamAt(0));
       await reader.LoadAsync((uint)stream.Size); var bytes = new byte[(int)stream.Size]; reader.ReadBytes(bytes);
       artwork = "data:" + (String.IsNullOrEmpty(stream.ContentType) ? "image/jpeg" : stream.ContentType) + ";base64," + Convert.ToBase64String(bytes);
      }
     }
    } catch { /* Missing artwork is allowed. Never invent a cover. */ }
   }
   var playing = pb.PlaybackStatus == GlobalSystemMediaTransportControlsSessionPlaybackStatus.Playing;
   double pos = tl.Position.TotalSeconds;
   if (playing && tl.LastUpdatedTime != default) pos += Math.Max(0, (DateTimeOffset.UtcNow - tl.LastUpdatedTime).TotalSeconds);
   var dur = Math.Max(0, (tl.EndTime - tl.StartTime).TotalSeconds);
   Emit(new { app = session.SourceAppUserModelId, title = props.Title, artist = props.Artist, album = props.AlbumTitle,
    playing, pos = Math.Clamp(pos - tl.StartTime.TotalSeconds, 0, dur > 0 ? dur : double.MaxValue), dur, art = artwork, commandError,
    canToggle = pb.Controls.IsPlayPauseToggleEnabled, canNext = pb.Controls.IsNextEnabled, canPrev = pb.Controls.IsPreviousEnabled });
  }
 } catch (Exception e) { Emit(new { none = true, err = e.Message }); }
 await Task.Delay(700);
}
