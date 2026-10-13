package cz.bliksoft.keepassaccess;

import java.io.IOException;

/**
 * A request to KeePass failed. Messages contain entry UUIDs and field names, never field values. The subclasses are
 * nested so callers can tell the causes apart.
 */
public class KeePassAccessException extends IOException {
	private static final long serialVersionUID = 1L;

	public KeePassAccessException(String message) {
		super(message);
	}

	public KeePassAccessException(String message, Throwable cause) {
		super(message, cause);
	}

	/** No KeePass with the KeePassAccess plugin is running for this user (the pipe does not exist). */
	public static class NotRunning extends KeePassAccessException {
		private static final long serialVersionUID = 1L;

		public NotRunning(String message, Throwable cause) {
			super(message, cause);
		}
	}

	/** KeePass runs, but no database is open and unlocked. */
	public static class Locked extends KeePassAccessException {
		private static final long serialVersionUID = 1L;

		public Locked(String message) {
			super(message);
		}
	}

	/** No entry with that UUID in the unlocked databases (or it is in the recycle bin). */
	public static class EntryNotFound extends KeePassAccessException {
		private static final long serialVersionUID = 1L;

		public EntryNotFound(String message) {
			super(message);
		}
	}

	/** The entry exists but is not tagged {@code ExternalAccess}. */
	public static class AccessDenied extends KeePassAccessException {
		private static final long serialVersionUID = 1L;

		public AccessDenied(String message) {
			super(message);
		}
	}

	/** A name tag is on more than one shared entry. */
	public static class Ambiguous extends KeePassAccessException {
		private static final long serialVersionUID = 1L;

		public Ambiguous(String message) {
			super(message);
		}
	}

	/** The entry has no such field. */
	public static class FieldNotFound extends KeePassAccessException {
		private static final long serialVersionUID = 1L;

		public FieldNotFound(String message) {
			super(message);
		}
	}
}
