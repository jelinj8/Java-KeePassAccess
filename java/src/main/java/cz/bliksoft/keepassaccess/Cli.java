package cz.bliksoft.keepassaccess;

import java.io.IOException;

/**
 * Diagnostics without revealing secrets: {@code ping}, {@code list} (UUID, title and name tags of shared entries)
 * and {@code fields <uuid|name>} (field names only). Exit code 0 on success, 1 on a KeePass error, 2 on bad usage.
 */
public final class Cli {
	private Cli() {
	}

	public static void main(String[] args) {
		System.exit(run(args));
	}

	static int run(String[] args) {
		if (args.length == 0)
			return usage();
		KeePassAccess kp = KeePassAccess.local();
		try {
			switch (args[0]) {
			case "ping":
				System.out.println("unlocked databases: " + kp.ping());
				return 0;
			case "list":
				for (EntryInfo e : kp.list())
					System.out.println(e.getUuid() + "  " + e.getTitle()
							+ (e.getNames().isEmpty() ? "" : "  [" + String.join(", ", e.getNames()) + "]"));
				return 0;
			case "fields":
				if (args.length != 2)
					return usage();
				for (String f : kp.entry(args[1]).keySet())
					System.out.println(f);
				return 0;
			default:
				return usage();
			}
		} catch (IllegalArgumentException e) {
			System.err.println(e.getMessage());
			return 2;
		} catch (IOException e) {
			System.err.println(e.getMessage());
			return 1;
		}
	}

	private static int usage() {
		System.err.println("usage: java -jar keepass-access.jar ping | list | fields <uuid|name>");
		return 2;
	}
}
