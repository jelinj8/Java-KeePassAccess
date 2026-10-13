using System.Reflection;
using System.Runtime.InteropServices;

// KeePass loads a DLL plugin only if its product name is "KeePass Plugin".
[assembly: AssemblyTitle("KeePassAccess")]
[assembly: AssemblyDescription("Serves entries tagged ExternalAccess to local programs of the same user over a named pipe.")]
[assembly: AssemblyCompany("Jakub Jelínek")]
[assembly: AssemblyProduct("KeePass Plugin")]
[assembly: AssemblyCopyright("Copyright © 2026 Jakub Jelínek")]
[assembly: ComVisible(false)]
[assembly: AssemblyVersion("1.2.0.0")]
[assembly: AssemblyFileVersion("1.2.0.0")]
