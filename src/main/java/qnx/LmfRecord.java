package qnx;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

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
	private byte recordType;
	private short dataNbytes;

	public LmfRecord(BinaryReader reader) throws IOException {
		recordType = reader.readNextByte();  // the record type
		reader.readNextByte();  // reserved
		dataNbytes = reader.readNextShort();  // size of the following data record
		reader.readNextShort();  // spare
	}

	public byte getRecordType() {
		return recordType;
	}

	public short getDataNbytes() {
		return dataNbytes;
	}
}
