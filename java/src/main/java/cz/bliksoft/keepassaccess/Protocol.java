package cz.bliksoft.keepassaccess;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Wire format of the KeePassAccess plugin. A request is one line ({@code PING}, {@code LIST}, {@code GET <uuid>}); a
 * response is a sequence of lines ending with an empty line. The first line is {@code OK[ <info>]} or
 * {@code ERR <code> <message>}; for LIST and GET the following lines are {@code <a>\t<b>} pairs, base64 (UTF-8) except
 * the entry UUID.
 */
public final class Protocol {
	/** Standard KeePass field names. */
	public static final String TITLE = "Title";
	public static final String USER_NAME = "UserName";
	public static final String PASSWORD = "Password";
	public static final String URL = "URL";
	public static final String NOTES = "Notes";

	private Protocol() {
	}

	/** 32 lower-case hex digits; dashes, braces and spaces are ignored. */
	public static String normalizeUuid(String uuid) {
		if (uuid == null)
			throw new IllegalArgumentException("entry UUID is missing");
		StringBuilder sb = new StringBuilder(32);
		for (int i = 0; i < uuid.length(); i++) {
			char c = uuid.charAt(i);
			if (c == '-' || c == '{' || c == '}' || c == ' ')
				continue;
			if (Character.digit(c, 16) < 0)
				throw new IllegalArgumentException("invalid entry UUID '" + uuid + "': expected 32 hex digits");
			sb.append(Character.toLowerCase(c));
		}
		if (sb.length() != 32)
			throw new IllegalArgumentException("invalid entry UUID '" + uuid + "': expected 32 hex digits");
		return sb.toString();
	}

	public static String pingRequest() {
		return "PING\n";
	}

	public static String listRequest() {
		return "LIST\n";
	}

	public static String getRequest(String uuid) {
		return "GET " + normalizeUuid(uuid).toUpperCase(Locale.ROOT) + "\n";
	}

	/** True for 32 hex digits (dashes, braces and spaces ignored): a reference is then a UUID, else a name tag. */
	public static boolean isUuid(String ref) {
		try {
			normalizeUuid(ref);
			return true;
		} catch (IllegalArgumentException e) {
			return false;
		}
	}

	/** A name tag: trimmed, not empty, one line, not the access tag itself. */
	public static String normalizeName(String name) {
		String n = name == null ? "" : name.strip();
		if (n.isEmpty() || n.indexOf('\n') >= 0 || n.indexOf('\r') >= 0 || n.equalsIgnoreCase(ACCESS_TAG))
			throw new IllegalArgumentException("invalid entry name tag '" + name + "'");
		return n;
	}

	public static String findRequest(String name) {
		return "FIND " + normalizeName(name) + "\n";
	}

	/** The tag that makes an entry readable at all. */
	public static final String ACCESS_TAG = "ExternalAccess";

	/** @return the number of unlocked databases */
	public static int parsePing(List<String> lines) throws KeePassAccessException {
		String info = ok(lines);
		try {
			return Integer.parseInt(info.trim());
		} catch (NumberFormatException e) {
			throw new KeePassAccessException("unexpected PING response");
		}
	}

	public static List<EntryInfo> parseList(List<String> lines) throws KeePassAccessException {
		ok(lines);
		List<EntryInfo> result = new ArrayList<>();
		for (String[] p : pairs(lines)) {
			// <uuid>\t<title>[\t<name tags, comma separated>] (plugin 1.2+ sends the tags)
			String rest = p[1];
			int tab = rest.indexOf('\t');
			List<String> tags = new ArrayList<>();
			if (tab >= 0) {
				for (String t : decode(rest.substring(tab + 1)).split(","))
					if (!t.isBlank())
						tags.add(t.strip());
				rest = rest.substring(0, tab);
			}
			result.add(new EntryInfo(normalizeUuid(p[0]), decode(rest), tags));
		}
		return Collections.unmodifiableList(result);
	}

	/** @return field name to value, in KeePass order */
	public static Map<String, String> parseGet(List<String> lines) throws KeePassAccessException {
		ok(lines);
		Map<String, String> fields = new LinkedHashMap<>();
		for (String[] p : pairs(lines))
			fields.put(decode(p[0]), decode(p[1]));
		return Collections.unmodifiableMap(fields);
	}

	/**
	 * Names of the protected fields of a GET/FIND response: fields KeePass protects (Password by default) or whose
	 * value comes from a reference. Plugin 1.4+ sends them in the status line, {@code OK protected=<b64>,<b64>}.
	 *
	 * @return the names, or {@code null} if the plugin does not report protection
	 */
	public static Set<String> parseProtected(List<String> lines) throws KeePassAccessException {
		for (String attr : ok(lines).split(" ")) {
			if (!attr.startsWith("protected="))
				continue;
			Set<String> names = new LinkedHashSet<>();
			for (String n : attr.substring("protected=".length()).split(","))
				if (!n.isEmpty())
					names.add(decode(n));
			return Collections.unmodifiableSet(names);
		}
		return null;
	}

	/** Checks the status line; @return the text after {@code OK}. */
	private static String ok(List<String> lines) throws KeePassAccessException {
		if (lines.isEmpty())
			throw new KeePassAccessException("empty response from KeePass");
		String first = lines.get(0);
		if (first.equals("OK"))
			return "";
		if (first.startsWith("OK "))
			return first.substring(3);
		if (first.startsWith("ERR ")) {
			String rest = first.substring(4);
			int sp = rest.indexOf(' ');
			String code = sp < 0 ? rest : rest.substring(0, sp);
			String msg = sp < 0 ? code : rest.substring(sp + 1);
			switch (code) {
			case "LOCKED":
				throw new KeePassAccessException.Locked("KeePass: " + msg);
			case "NOT_FOUND":
				throw new KeePassAccessException.EntryNotFound("KeePass: " + msg);
			case "DENIED":
				throw new KeePassAccessException.AccessDenied("KeePass: " + msg);
			case "AMBIGUOUS":
				throw new KeePassAccessException.Ambiguous("KeePass: " + msg);
			default:
				throw new KeePassAccessException("KeePass: " + code + " " + msg);
			}
		}
		throw new KeePassAccessException("unexpected response from KeePass");
	}

	private static List<String[]> pairs(List<String> lines) throws KeePassAccessException {
		List<String[]> result = new ArrayList<>();
		for (int i = 1; i < lines.size(); i++) {
			String l = lines.get(i);
			if (l.isEmpty())
				break;
			int tab = l.indexOf('\t');
			if (tab < 0)
				throw new KeePassAccessException("malformed response line " + (i + 1) + " from KeePass");
			result.add(new String[] { l.substring(0, tab), l.substring(tab + 1) });
		}
		return result;
	}

	private static String decode(String b64) throws KeePassAccessException {
		try {
			return new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8);
		} catch (IllegalArgumentException e) {
			throw new KeePassAccessException("malformed base64 in response from KeePass");
		}
	}
}
