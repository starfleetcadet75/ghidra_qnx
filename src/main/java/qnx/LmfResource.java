package qnx;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

/**
 * A class to represent the lmf_resource struct as defined in
 * <code>exeqnx.h</code>. <br>
 * 
 * <pre>
 * typedef struct lmf_resource {
 *     unsigned_16 res_type;
 *     unsigned_16 spare[3];
 * } lmf_resource;
 * </pre>
 * 
 * @see <a href=
 *      "https://github.com/open-watcom/open-watcom-v2/blob/57ba42ef9e97d074577a3408bb8f28a586c902f7/bld/watcom/h/exeqnx.h#L110">watcom/h/exeqnx.h</a>
 */
public class LmfResource {
	private short resourceType;

	public LmfResource(BinaryReader reader, LmfRecord record) throws IOException {
		resourceType = reader.readNextShort();
		reader.readNextShortArray(3);
		int size = record.getDataNbytes() - LmfConstants.LMF_RESOURCE_SIZE;

		// Jump the reader past the resource content to the start of the next record
		reader.setPointerIndex(reader.getPointerIndex() + size);
	}

	public short getType() {
		return resourceType;
	}
}
