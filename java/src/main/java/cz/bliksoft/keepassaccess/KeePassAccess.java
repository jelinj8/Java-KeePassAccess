package cz.bliksoft.keepassaccess;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Reads entries from a running, unlocked KeePass 2.x with the KeePassAccess plugin. Only entries tagged
 * {@code ExternalAccess} are served. An entry is referenced by its UUID or by a name: another tag of the entry,
 * which must be unique among the shared entries (plugin 1.2+). Name tags make references portable between
 * databases, e.g. a shared configuration where every user has their own entry with the same name tag. Entries are
 * cached per instance, so repeated lookups cost one request.
 *
 * <pre>
 * KeePassAccess kp = KeePassAccess.local();
 * String password = kp.password("3F2504E04F8911D39A0C0305E82C3301");
 * String user = kp.field("app-db-user", Protocol.USER_NAME);
 * </pre>
 *
 * Not thread-safe. Values are never logged or put into exception messages.
 */
public final class KeePassAccess {
	private final Transport transport;
	private final Map<String, Entry> cache = new HashMap<>();

	public KeePassAccess(Transport transport) {
		this.transport = transport;
	}

	/** KeePass of the current Windows user. */
	public static KeePassAccess local() {
		return new KeePassAccess(PipeTransport.local());
	}

	/** @return the number of unlocked databases (0 = KeePass runs but everything is locked) */
	public int ping() throws IOException {
		return Protocol.parsePing(transport.exchange(Protocol.pingRequest()));
	}

	/** Shared entries (UUID, title, name tags). */
	public List<EntryInfo> list() throws IOException {
		return Protocol.parseList(transport.exchange(Protocol.listRequest()));
	}

	/**
	 * All fields of an entry: Title, UserName, Password, URL, Notes and custom string fields.
	 *
	 * @param ref entry UUID (32 hex digits, dashes and braces allowed) or name tag
	 */
	public Map<String, String> entry(String ref) throws IOException {
		return load(ref).fields;
	}

	/**
	 * Names of the entry's protected fields: fields KeePass protects (Password by default, custom fields with
	 * in-memory protection) or whose value comes from a reference. Values of all fields are returned by
	 * {@link #entry} and {@link #field} as usual; this only tells which ones are secret.
	 *
	 * @return the names, or {@code null} if the plugin does not report protection (plugin before 1.4)
	 */
	public Set<String> protectedFields(String ref) throws IOException {
		return load(ref).protectedNames;
	}

	private Entry load(String ref) throws IOException {
		boolean byUuid = Protocol.isUuid(ref);
		String key = byUuid ? Protocol.normalizeUuid(ref) : "name:" + Protocol.normalizeName(ref).toLowerCase(Locale.ROOT);
		Entry e = cache.get(key);
		if (e == null) {
			String request = byUuid ? Protocol.getRequest(ref) : Protocol.findRequest(ref);
			List<String> lines = transport.exchange(request);
			e = new Entry(Protocol.parseGet(lines), Protocol.parseProtected(lines));
			cache.put(key, e);
		}
		return e;
	}

	private static final class Entry {
		final Map<String, String> fields;
		final Set<String> protectedNames;

		Entry(Map<String, String> fields, Set<String> protectedNames) {
			this.fields = fields;
			this.protectedNames = protectedNames;
		}
	}

	/** One field; the name is matched exactly first, then case-insensitively. */
	public String field(String ref, String field) throws IOException {
		Map<String, String> e = entry(ref);
		String v = e.get(field);
		if (v == null)
			for (Map.Entry<String, String> f : e.entrySet())
				if (f.getKey().equalsIgnoreCase(field))
					return f.getValue();
		if (v == null)
			throw new KeePassAccessException.FieldNotFound("entry " + ref.strip() + " has no field '" + field + "'");
		return v;
	}

	/** The password of an entry. */
	public String password(String ref) throws IOException {
		return field(ref, Protocol.PASSWORD);
	}
}
