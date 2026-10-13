package cz.bliksoft.keepassaccess;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Windows named pipe {@code \\.\pipe\KeePassAccess-<user>} served by the plugin, one connection per request. The pipe
 * accepts only the Windows user that runs KeePass.
 */
public final class PipeTransport implements Transport {
	/** Overrides the pipe name (system property or environment variable). */
	public static final String PIPE_PROPERTY = "keepassaccess.pipe";
	public static final String PIPE_ENV = "KEEPASS_ACCESS_PIPE";

	private static final long DEFAULT_WAIT_MS = 3000;

	private final String pipeName;
	private final long waitMs;

	public PipeTransport(String pipeName, long waitMs) {
		this.pipeName = pipeName;
		this.waitMs = waitMs;
	}

	/** The pipe of the current user (same name the plugin uses), unless overridden. */
	public static PipeTransport local() {
		String name = System.getProperty(PIPE_PROPERTY);
		if (name == null || name.isBlank())
			name = System.getenv(PIPE_ENV);
		if (name == null || name.isBlank())
			name = "KeePassAccess-" + System.getProperty("user.name");
		return new PipeTransport(name, DEFAULT_WAIT_MS);
	}

	public String getPipeName() {
		return pipeName;
	}

	@Override
	public List<String> exchange(String request) throws IOException {
		try (RandomAccessFile pipe = open()) {
			pipe.write(request.getBytes(StandardCharsets.UTF_8));
			ByteArrayOutputStream buf = new ByteArrayOutputStream();
			byte[] chunk = new byte[4096];
			while (!complete(buf)) {
				int n;
				try {
					n = pipe.read(chunk);
				} catch (IOException e) {
					n = -1; // Windows reports the server's disconnect as an error
				}
				if (n < 0)
					break;
				buf.write(chunk, 0, n);
			}
			if (!complete(buf))
				throw new KeePassAccessException("incomplete response from KeePass on pipe " + pipeName);
			String text = new String(buf.toByteArray(), StandardCharsets.UTF_8);
			return new ArrayList<>(Arrays.asList(text.split("\n", -1)));
		}
	}

	/**
	 * The plugin serves one client at a time; between two clients the pipe briefly does not exist or is busy, so
	 * opening is retried for a short while before KeePass is considered not running.
	 */
	private RandomAccessFile open() throws IOException {
		String path = "\\\\.\\pipe\\" + pipeName;
		long deadline = System.currentTimeMillis() + waitMs;
		while (true) {
			try {
				return new RandomAccessFile(path, "rw");
			} catch (FileNotFoundException e) {
				if (System.currentTimeMillis() >= deadline)
					throw new KeePassAccessException.NotRunning("KeePass with the KeePassAccess plugin is not running "
							+ "for this user (pipe " + pipeName + " not available)", e);
				try {
					Thread.sleep(50);
				} catch (InterruptedException ie) {
					Thread.currentThread().interrupt();
					throw new KeePassAccessException("interrupted while connecting to KeePass", ie);
				}
			}
		}
	}

	/** A response ends with an empty line, i.e. "\n\n". */
	private static boolean complete(ByteArrayOutputStream buf) {
		byte[] b = buf.toByteArray();
		return b.length >= 2 && b[b.length - 1] == '\n' && b[b.length - 2] == '\n';
	}
}
