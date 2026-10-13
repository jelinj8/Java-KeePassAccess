// KeePassAccess - serves entries tagged "ExternalAccess" of the unlocked KeePass databases to local programs of the
// same Windows user over a named pipe. Protocol: see README.md. C# 5 / .NET Framework 4 (csc.exe of the framework).
// Author: Jakub Jelínek
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;

using KeePass.Plugins;
using KeePass.Util.Spr;
using KeePassLib;
using KeePassLib.Security;

namespace KeePassAccess
{
	public sealed class KeePassAccessExt : Plugin
	{
		/// <summary>Only entries with this tag (case-insensitive) are served.</summary>
		public const string AccessTag = "ExternalAccess";

		private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);

		private IPluginHost host;
		private Thread worker;
		private volatile bool stopping;
		private string pipeName;

		public static string PipeNameFor(string userName)
		{
			return "KeePassAccess-" + userName;
		}

		public override bool Initialize(IPluginHost pluginHost)
		{
			if (pluginHost == null)
				return false;
			host = pluginHost;
			pipeName = PipeNameFor(Environment.UserName);
			worker = new Thread(Serve);
			worker.IsBackground = true;
			worker.Name = "KeePassAccess pipe server";
			worker.Start();
			return true;
		}

		/// <summary>
		/// Entry context menu item "Allow external access": sets or clears the tag on the selected entries, so the
		/// tag does not have to be typed (KeePass only suggests tags that some entry already has).
		/// </summary>
		public override ToolStripMenuItem GetMenuItem(PluginMenuType t)
		{
			if (t != PluginMenuType.Entry)
				return null;
			ToolStripMenuItem mi = new ToolStripMenuItem("Allow External Access (tag " + AccessTag + ")");
			mi.Click += delegate { ToggleSelected(); };
			mi.OwnerChanged += delegate
			{
				ToolStripDropDown menu = mi.Owner as ToolStripDropDown;
				if (menu != null)
					menu.Opening += delegate { UpdateMenuItem(mi); };
			};
			return mi;
		}

		private void UpdateMenuItem(ToolStripMenuItem mi)
		{
			PwEntry[] sel = host.MainWindow.GetSelectedEntries();
			mi.Enabled = sel != null && sel.Length > 0;
			mi.Checked = mi.Enabled && AllTagged(sel);
		}

		private static bool AllTagged(PwEntry[] entries)
		{
			foreach (PwEntry e in entries)
				if (!HasTag(e))
					return false;
			return true;
		}

		/// <summary>All selected tagged: remove the tag from all; otherwise add it to the untagged ones.</summary>
		private void ToggleSelected()
		{
			PwEntry[] sel = host.MainWindow.GetSelectedEntries();
			if (sel == null || sel.Length == 0)
				return;
			bool remove = AllTagged(sel);
			foreach (PwEntry e in sel)
			{
				if (remove)
				{
					List<string> tags = new List<string>();
					foreach (string tag in e.Tags)
						if (!string.Equals(tag, AccessTag, StringComparison.OrdinalIgnoreCase))
							tags.Add(tag);
					e.Tags = tags;
				}
				else if (!HasTag(e))
					e.AddTag(AccessTag);
				else
					continue;
				e.Touch(true, false);
			}
			// refresh the entry list and mark the active database as modified
			host.MainWindow.UpdateUI(false, null, false, null, true, null, true);
		}

		public override void Terminate()
		{
			stopping = true;
			try
			{
				// wake up WaitForConnection
				using (NamedPipeClientStream c = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut))
					c.Connect(500);
			}
			catch (Exception) { }
			if (worker != null)
				worker.Join(2000);
		}

		private static PipeSecurity CurrentUserOnly()
		{
			PipeSecurity ps = new PipeSecurity();
			ps.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User, PipeAccessRights.FullControl,
				AccessControlType.Allow));
			return ps;
		}

		private void Serve()
		{
			while (!stopping)
			{
				try
				{
					using (NamedPipeServerStream pipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1,
						PipeTransmissionMode.Byte, PipeOptions.None, 4096, 4096, CurrentUserOnly()))
					{
						pipe.WaitForConnection();
						if (stopping)
							break;
						HandleClient(pipe);
					}
				}
				catch (Exception)
				{
					// a broken client must not stop the server; avoid a busy loop on persistent errors
					if (!stopping)
						Thread.Sleep(200);
				}
			}
		}

		private void HandleClient(NamedPipeServerStream pipe)
		{
			StreamReader reader = new StreamReader(pipe, Utf8, false, 4096, true);
			string request = reader.ReadLine();
			string response;
			try
			{
				response = Answer(request == null ? "" : request.Trim());
			}
			catch (Exception e)
			{
				response = Err("BAD_REQUEST", e.GetType().Name);
			}
			byte[] bytes = Utf8.GetBytes(response);
			pipe.Write(bytes, 0, bytes.Length);
			pipe.Flush();
			pipe.WaitForPipeDrain();
			pipe.Disconnect();
		}

		/// <summary>Every response is a sequence of lines terminated by an empty line.</summary>
		private string Answer(string request)
		{
			string cmd = request;
			string arg = "";
			int sp = request.IndexOf(' ');
			if (sp > 0)
			{
				cmd = request.Substring(0, sp);
				arg = request.Substring(sp + 1).Trim();
			}
			switch (cmd.ToUpperInvariant())
			{
				case "PING":
					return OnUiThread(delegate { return "OK " + OpenDatabases().Count + "\n\n"; });
				case "LIST":
					return OnUiThread(List);
				case "GET":
					PwUuid uuid = ParseUuid(arg);
					if (uuid == null)
						return Err("BAD_REQUEST", "GET needs an entry UUID (32 hex digits)");
					return OnUiThread(delegate { return Get(uuid); });
				case "FIND":
					if (arg.Length == 0 || string.Equals(arg, AccessTag, StringComparison.OrdinalIgnoreCase))
						return Err("BAD_REQUEST", "FIND needs a name tag (other than " + AccessTag + ")");
					return OnUiThread(delegate { return Find(arg); });
				default:
					return Err("BAD_REQUEST", "unknown command; use PING, LIST, GET <uuid> or FIND <name>");
			}
		}

		private string OnUiThread(Func<string> f)
		{
			// KeePass objects are not thread-safe: touch them on the UI thread only
			return (string)host.MainWindow.Invoke(f);
		}

		private List<PwDatabase> OpenDatabases()
		{
			List<PwDatabase> result = new List<PwDatabase>();
			foreach (PwDatabase db in host.MainWindow.DocumentManager.GetOpenDatabases())
				if (db != null && db.IsOpen)
					result.Add(db);
			return result;
		}

		private string List()
		{
			List<PwDatabase> dbs = OpenDatabases();
			if (dbs.Count == 0)
				return Err("LOCKED", "no unlocked database");
			StringBuilder sb = new StringBuilder("OK\n");
			foreach (PwDatabase db in dbs)
			{
				foreach (PwEntry e in db.RootGroup.GetEntries(true))
				{
					if (!IsShared(db, e))
						continue;
					sb.Append(e.Uuid.ToHexString()).Append('\t')
						.Append(B64(e.Strings.ReadSafe(PwDefs.TitleField))).Append('\t')
						.Append(B64(string.Join(",", NameTags(e).ToArray()))).Append('\n');
				}
			}
			return sb.Append('\n').ToString();
		}

		/// <summary>The entry with this UUID. A copied entry keeps its UUID, so it may be in several databases: the
		/// copy tagged AccessTag is served, untagged copies are ignored, several tagged copies are AMBIGUOUS.</summary>
		private string Get(PwUuid uuid)
		{
			List<PwDatabase> dbs = OpenDatabases();
			if (dbs.Count == 0)
				return Err("LOCKED", "no unlocked database");
			bool exists = false;
			PwDatabase foundDb = null;
			PwEntry found = null;
			List<string> dbNames = new List<string>();
			foreach (PwDatabase db in dbs)
			{
				PwEntry e = db.RootGroup.FindEntry(uuid, true);
				if (e == null || InRecycleBin(db, e))
					continue;
				exists = true;
				if (!HasTag(e))
					continue;
				foundDb = db;
				found = e;
				dbNames.Add(DisplayName(db));
			}
			if (!exists)
				return Err("NOT_FOUND", "entry " + uuid.ToHexString() + " not found in the unlocked databases");
			if (dbNames.Count == 0)
				return Err("DENIED", "entry " + uuid.ToHexString() + " is not tagged " + AccessTag);
			if (dbNames.Count > 1)
				return Err("AMBIGUOUS", "entry " + uuid.ToHexString() + " is shared in " + dbNames.Count
					+ " databases: " + string.Join(", ", dbNames.ToArray()));
			return Fields(foundDb, found);
		}

		private static string DisplayName(PwDatabase db)
		{
			if (!string.IsNullOrEmpty(db.Name))
				return db.Name;
			return db.IOConnectionInfo.GetDisplayName();
		}

		/// <summary>The shared entry (tagged AccessTag) that also carries the tag <paramref name="name"/>; it must
		/// be unique over all unlocked databases. Entries with that tag but without AccessTag are ignored.</summary>
		private string Find(string name)
		{
			List<PwDatabase> dbs = OpenDatabases();
			if (dbs.Count == 0)
				return Err("LOCKED", "no unlocked database");
			PwDatabase foundDb = null;
			PwEntry found = null;
			List<string> titles = new List<string>();
			foreach (PwDatabase db in dbs)
			{
				foreach (PwEntry e in db.RootGroup.GetEntries(true))
				{
					if (!IsShared(db, e) || !HasTag(e, name))
						continue;
					foundDb = db;
					found = e;
					titles.Add(e.Strings.ReadSafe(PwDefs.TitleField));
				}
			}
			if (titles.Count == 0)
				return Err("NOT_FOUND", "no entry tagged " + AccessTag + " and " + name + " in the unlocked databases");
			if (titles.Count > 1)
				return Err("AMBIGUOUS", "tag " + name + " is on " + titles.Count + " shared entries: "
					+ string.Join(", ", titles.ToArray()));
			return Fields(foundDb, found);
		}

		/// <summary>
		/// Status line "OK protected=&lt;b64 name&gt;,..." (plugin 1.4+; older clients ignore the text after OK), then
		/// one line per field. A field is protected if KeePass protects it or if a placeholder changed its value: a
		/// {REF:...} may pull in another entry's password.
		/// </summary>
		private static string Fields(PwDatabase db, PwEntry e)
		{
			StringBuilder lines = new StringBuilder();
			List<string> protectedNames = new List<string>();
			SprContext ctx = new SprContext(e, db, SprCompileFlags.Deref);
			foreach (KeyValuePair<string, ProtectedString> kv in e.Strings)
			{
				string raw = kv.Value.ReadString();
				string value = raw;
				if (value.IndexOf('{') >= 0)
					value = SprEngine.Compile(value, ctx); // {REF:...} as KeePass shows it; no commands
				if (kv.Value.IsProtected || value != raw)
					protectedNames.Add(B64(kv.Key));
				lines.Append(B64(kv.Key)).Append('\t').Append(B64(value)).Append('\n');
			}
			return "OK protected=" + string.Join(",", protectedNames.ToArray()) + "\n" + lines.Append('\n');
		}

		/// <summary>The entry's tags except AccessTag: its names for FIND.</summary>
		private static List<string> NameTags(PwEntry e)
		{
			List<string> names = new List<string>();
			foreach (string t in e.Tags)
				if (!string.Equals(t, AccessTag, StringComparison.OrdinalIgnoreCase))
					names.Add(t);
			return names;
		}

		private static bool IsShared(PwDatabase db, PwEntry e)
		{
			return HasTag(e) && !InRecycleBin(db, e);
		}

		private static bool HasTag(PwEntry e)
		{
			return HasTag(e, AccessTag);
		}

		private static bool HasTag(PwEntry e, string tag)
		{
			foreach (string t in e.Tags)
				if (string.Equals(t, tag, StringComparison.OrdinalIgnoreCase))
					return true;
			return false;
		}

		private static bool InRecycleBin(PwDatabase db, PwEntry e)
		{
			if (!db.RecycleBinEnabled || db.RecycleBinUuid == null || db.RecycleBinUuid.Equals(PwUuid.Zero))
				return false;
			for (PwGroup g = e.ParentGroup; g != null; g = g.ParentGroup)
				if (g.Uuid.Equals(db.RecycleBinUuid))
					return true;
			return false;
		}

		/// <summary>32 hex digits; dashes, braces and spaces are ignored.</summary>
		internal static PwUuid ParseUuid(string s)
		{
			StringBuilder hex = new StringBuilder();
			foreach (char c in s)
			{
				if (c == '-' || c == '{' || c == '}' || c == ' ')
					continue;
				if (!Uri.IsHexDigit(c))
					return null;
				hex.Append(c);
			}
			if (hex.Length != 32)
				return null;
			byte[] b = new byte[16];
			for (int i = 0; i < 16; i++)
				b[i] = Convert.ToByte(hex.ToString(i * 2, 2), 16);
			return new PwUuid(b);
		}

		private static string B64(string s)
		{
			return Convert.ToBase64String(Utf8.GetBytes(s ?? ""));
		}

		private static string Err(string code, string message)
		{
			return "ERR " + code + " " + message.Replace('\n', ' ') + "\n\n";
		}
	}
}
