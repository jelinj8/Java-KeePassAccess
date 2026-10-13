package cz.bliksoft.keepassaccess;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class ProtocolTest {
	static final String UUID = "3f2504e04f8911d39a0c0305e82c3301";

	static String b64(String s) {
		return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
	}

	static List<String> lines(String... l) {
		return Arrays.asList(l);
	}

	@Test
	void uuidNormalization() {
		assertEquals(UUID, Protocol.normalizeUuid("3F2504E0-4F89-11D3-9A0C-0305E82C3301"));
		assertEquals(UUID, Protocol.normalizeUuid("{3F2504E04F8911D39A0C0305E82C3301}"));
		assertEquals("GET 3F2504E04F8911D39A0C0305E82C3301\n", Protocol.getRequest(UUID));
		assertThrows(IllegalArgumentException.class, () -> Protocol.normalizeUuid("3F2504E0"));
		assertThrows(IllegalArgumentException.class, () -> Protocol.normalizeUuid("zz2504e04f8911d39a0c0305e82c3301"));
		assertThrows(IllegalArgumentException.class, () -> Protocol.normalizeUuid(null));
	}

	@Test
	void getResponse() throws Exception {
		Map<String, String> f = Protocol.parseGet(lines("OK", b64("UserName") + "\t" + b64("appuser"),
				b64("Password") + "\t" + b64("pä\tss\nword"), b64("HOST") + "\t" + b64(""), "", ""));
		assertEquals(Arrays.asList("UserName", "Password", "HOST"), Arrays.asList(f.keySet().toArray()));
		assertEquals("pä\tss\nword", f.get("Password"));
		assertEquals("", f.get("HOST"));
	}

	@Test
	void listAndPing() throws Exception {
		List<EntryInfo> l = Protocol.parseList(lines("OK", UUID.toUpperCase() + "\t" + b64("App DB user"), "", ""));
		assertEquals(1, l.size());
		assertEquals(UUID, l.get(0).getUuid());
		assertEquals("App DB user", l.get(0).getTitle());
		assertTrue(Protocol.parseList(lines("OK", "", "")).isEmpty());
		assertEquals(2, Protocol.parsePing(lines("OK 2", "", "")));
	}

	@Test
	void namesAndListTags() throws Exception {
		assertTrue(Protocol.isUuid("{3F2504E0-4F89-11D3-9A0C-0305E82C3301}"));
		assertFalse(Protocol.isUuid("app-db-user"));
		assertFalse(Protocol.isUuid("3F2504E0")); // too short: a name
		assertEquals("FIND app-db-user\n", Protocol.findRequest("  app-db-user "));
		assertEquals("FIND App DB\n", Protocol.findRequest("App DB"));
		assertThrows(IllegalArgumentException.class, () -> Protocol.findRequest(" "));
		assertThrows(IllegalArgumentException.class, () -> Protocol.findRequest("externalaccess"));
		assertThrows(IllegalArgumentException.class, () -> Protocol.findRequest("a\nGET x"));

		List<EntryInfo> l = Protocol.parseList(lines("OK", UUID + "\t" + b64("App DB") + "\t" + b64("app-db-user, shared"),
				UUID + "\t" + b64("no names") + "\t" + b64(""), "", ""));
		assertEquals(Arrays.asList("app-db-user", "shared"), l.get(0).getNames());
		assertTrue(l.get(1).getNames().isEmpty());
		assertThrows(KeePassAccessException.Ambiguous.class,
				() -> Protocol.parseGet(lines("ERR AMBIGUOUS tag x is on 2 shared entries: A, B", "", "")));
	}

	@Test
	void errorsMapToExceptions() {
		assertThrows(KeePassAccessException.Locked.class,
				() -> Protocol.parseGet(lines("ERR LOCKED no unlocked database", "", "")));
		assertThrows(KeePassAccessException.EntryNotFound.class,
				() -> Protocol.parseGet(lines("ERR NOT_FOUND entry x not found", "", "")));
		KeePassAccessException denied = assertThrows(KeePassAccessException.AccessDenied.class,
				() -> Protocol.parseGet(lines("ERR DENIED entry x is not tagged ExternalAccess", "", "")));
		assertTrue(denied.getMessage().contains("not tagged ExternalAccess"));
		KeePassAccessException other = assertThrows(KeePassAccessException.class,
				() -> Protocol.parseGet(lines("ERR BAD_REQUEST unknown command", "", "")));
		assertFalse(other instanceof KeePassAccessException.Locked);
		assertThrows(KeePassAccessException.class, () -> Protocol.parseGet(lines("HELLO", "")));
		assertThrows(KeePassAccessException.class, () -> Protocol.parseGet(lines("OK", "no-tab", "")));
		assertThrows(KeePassAccessException.class, () -> Protocol.parseGet(lines("OK", "a\t!!!", "")));
		assertThrows(KeePassAccessException.class, () -> Protocol.parsePing(lines()));
	}
}
