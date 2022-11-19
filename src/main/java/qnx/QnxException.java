package qnx;

/**
 * An exception class to handle encountering invalid lmf_headers.
 */
public class QnxException extends Exception {

	/**
	 * Constructs a new exception with the specified detail message.
	 * @param   message   the detail message.
	 */
	public QnxException(String message) {
		super(message);
	}
}
