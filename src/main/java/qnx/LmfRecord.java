package qnx;

import java.io.IOException;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;

/**
 * A class to represent the lmf_record struct as defined in
 * <code>exeqnx.h</code>. <br>
 * 
 * <pre>
 * typedef struct lmf_record {
 *     unsigned_8    rec_type;
 *     unsigned_8    reserved;     // must be 0  
 *     unsigned_16   data_nbytes;  // size of the following data record  
 *     unsigned_16   spare;        // must be 0
 * } lmf_record;
 * </pre>
 * 
 * @see <a href=
 *      "https://github.com/open-watcom/open-watcom-v2/blob/57ba42ef9e97d074577a3408bb8f28a586c902f7/bld/watcom/h/exeqnx.h#L83">watcom/h/exeqnx.h</a>
 */
public class LmfRecord {
	private byte recType;
	private short dataNbytes;

	public static LmfRecord createLmfRecord(FactoryBundledWithBinaryReader reader) throws IOException {
		LmfRecord lmfRecord = (LmfRecord) reader.getFactory().create(LmfRecord.class);
		lmfRecord.initLmfRecord(reader);
		return lmfRecord;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS
	 * INSTEAD.
	 */
	public LmfRecord() {
	}

	private void initLmfRecord(FactoryBundledWithBinaryReader reader) throws IOException {
		recType = reader.readNextByte();
		reader.readNextByte();
		dataNbytes = reader.readNextShort();
		reader.readNextShort();
	}

	public byte getType() {
		return recType;
	}

	public short getDataNbytes() {
		return dataNbytes;
	}
}
