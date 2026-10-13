package cz.bliksoft.keepassaccess;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/** An entry KeePass shares (tagged {@code ExternalAccess}): UUID, title and name tags, no secret values. */
public final class EntryInfo {
	private final String uuid;
	private final String title;
	private final List<String> names;

	public EntryInfo(String uuid, String title) {
		this(uuid, title, Collections.<String>emptyList());
	}

	public EntryInfo(String uuid, String title, List<String> names) {
		this.uuid = uuid;
		this.title = title;
		this.names = Collections.unmodifiableList(names);
	}

	/** 32 lower-case hex digits. */
	public String getUuid() {
		return uuid;
	}

	public String getTitle() {
		return title;
	}

	/** The entry's other tags, usable as names instead of the UUID (empty with plugins before 1.2). */
	public List<String> getNames() {
		return names;
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof EntryInfo))
			return false;
		EntryInfo e = (EntryInfo) o;
		return e.uuid.equals(uuid) && Objects.equals(e.title, title) && e.names.equals(names);
	}

	@Override
	public int hashCode() {
		return uuid.hashCode();
	}

	@Override
	public String toString() {
		return uuid + " " + title + (names.isEmpty() ? "" : " " + names);
	}
}
