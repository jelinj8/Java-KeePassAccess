package cz.bliksoft.keepassaccess;

import static cz.bliksoft.keepassaccess.ProtocolTest.UUID;
import static cz.bliksoft.keepassaccess.ProtocolTest.b64;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

class KeePassAccessTest {
	/** Answers every GET with the same entry and records the requests. */
	static final class FakeTransport implements Transport {
		final List<String> requests = new ArrayList<>();

		@Override
		public List<String> exchange(String request) {
			requests.add(request);
			return Arrays.asList("OK", b64("UserName") + "\t" + b64("appuser"), b64("Password") + "\t" + b64("s3cret"),
					b64("SERVICE") + "\t" + b64("APPDB.EXAMPLE"), "", "");
		}
	}

	@Test
	void fieldsAndCaching() throws Exception {
		FakeTransport t = new FakeTransport();
		KeePassAccess kp = new KeePassAccess(t);
		assertEquals("s3cret", kp.password(UUID));
		assertEquals("appuser", kp.field(UUID.toUpperCase(), "username")); // case-insensitive fallback
		assertEquals("APPDB.EXAMPLE", kp.field("{" + UUID + "}", "SERVICE"));
		assertEquals(1, t.requests.size(), "one request per entry");
	}

	@Test
	void protectedFieldsShareTheCachedRequest() throws Exception {
		List<String> requests = new ArrayList<>();
		KeePassAccess kp = new KeePassAccess(request -> {
			requests.add(request);
			return Arrays.asList("OK protected=" + b64("Password"), b64("UserName") + "\t" + b64("appuser"),
					b64("Password") + "\t" + b64("s3cret"), "", "");
		});
		assertEquals(Collections.singleton("Password"), kp.protectedFields("app-db-user"));
		assertEquals("appuser", kp.field("app-db-user", "UserName"));
		assertEquals(1, requests.size());
		assertNull(new KeePassAccess(new FakeTransport()).protectedFields(UUID), "plugin before 1.4");
	}

	@Test
	void namesUseFindAndAreCachedCaseInsensitively() throws Exception {
		FakeTransport t = new FakeTransport();
		KeePassAccess kp = new KeePassAccess(t);
		assertEquals("s3cret", kp.password("app-db-user"));
		assertEquals("appuser", kp.field("APP-DB-USER", "UserName"));
		assertEquals(Arrays.asList("FIND app-db-user\n"), t.requests);
	}

	@Test
	void missingFieldNamesTheFieldButNotValues() {
		KeePassAccess kp = new KeePassAccess(new FakeTransport());
		KeePassAccessException e = assertThrows(KeePassAccessException.FieldNotFound.class, () -> kp.field(UUID, "PORT"));
		assertTrue(e.getMessage().contains("'PORT'"));
		assertFalse(e.getMessage().contains("s3cret"));
	}

	@Test
	void missingPipeMeansNotRunning() {
		PipeTransport t = new PipeTransport("KeePassAccess-test-" + System.nanoTime(), 100);
		KeePassAccessException e = assertThrows(KeePassAccessException.NotRunning.class,
				() -> new KeePassAccess(t).ping());
		assertTrue(e.getMessage().contains("not running"));
	}
}
