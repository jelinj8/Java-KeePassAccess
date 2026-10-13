package cz.bliksoft.keepassaccess;

import java.io.IOException;
import java.util.List;

/** Sends one request line and returns the response lines (up to and including the terminating empty line). */
public interface Transport {
	List<String> exchange(String request) throws IOException;
}
