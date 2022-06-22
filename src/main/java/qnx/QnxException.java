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

	/**
	 * Constructs a new exception with the specified cause and a detail message.
	 * @param  cause the cause (which is saved for later retrieval by the method
	 */
	public QnxException(Exception cause) {
		super(cause);
	}
}
