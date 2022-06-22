package qnx;

public class LmfConstants {
	/**
	 * The signature for QNX executables.
	 */
	public final static byte[] QNX_SIGNATURE = new byte[] { 0x00, 0x00, 0x38, 0x00, 0x00, 0x00 };

	public final static int LMF_RECORD_SIZE = 6;

	public final static int LMF_HEADER_SIZE = 48;

	public final static int LMF_DATA_SIZE = 6;

	public final static int LMF_RESOURCE_SIZE = 8;

	public static final int LMF_HEADER_REC = 0;

	public static final int LMF_COMMENT_REC = 1;

	public static final int LMF_LOAD_REC = 2;

	public static final int LMF_FIXUP_REC = 3;

	public static final int LMF_8087_FIXUP_REC = 4;

	public static final int LMF_IMAGE_END_REC = 5;

	public static final int LMF_RESOURCE_REC = 6;

	public static final int LMF_RW_END_REC = 7;

	public static final int LMF_LINEAR_FIXUP_REC = 8;
}
