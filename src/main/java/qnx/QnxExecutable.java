package qnx;

import java.io.IOException;
import java.util.Arrays;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.util.Msg;

/**
 * A class to manage loading QNX executables.
 */
public class QnxExecutable {
	private FactoryBundledWithBinaryReader reader;
	private LmfHeader header;
	private short verify;
	private int signature;

	public static QnxExecutable createQnxExecutable(GenericFactory factory, ByteProvider provider)
			throws IOException, QnxException {
		QnxExecutable qnx = (QnxExecutable) factory.create(QnxExecutable.class);
		qnx.initQnxExecutable(factory, provider);
		return qnx;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS
	 * INSTEAD.
	 */
	public QnxExecutable() {
	}

	private void initQnxExecutable(GenericFactory factory, ByteProvider provider) throws IOException, QnxException {
		reader = new FactoryBundledWithBinaryReader(factory, provider, true);

		// First 6 bytes are the magic signature
		byte[] magicBytes = reader.readByteArray(0, 6);
		if (!Arrays.equals(magicBytes, LmfConstants.QNX_SIGNATURE)) {
			throw new QnxException("Not a valid QNX executable");
		}

		// First 6 bytes are also the first LMF_RECORD
		LmfRecord record = LmfRecord.createLmfRecord(reader);
		int nsegments = (record.getDataNbytes() - LmfConstants.LMF_HEADER_SIZE) / 4;

		this.header = LmfHeader.createLmfHeader(reader, nsegments);
	}

	public void parse() throws IOException, QnxException {
		if (reader == null) {
			throw new IOException("QNX binary reader is null");
		}

		// Continue parsing records until an image end record is encountered
		while (true) {
			LmfRecord record = LmfRecord.createLmfRecord(reader);
			int recordType = record.getType();

			Msg.debug(this, "Parsing record type: " + recordType);

			if (recordType == LmfConstants.LMF_IMAGE_END_REC) {
				// Processing is complete when an image end record is encountered
				break;
			}

			switch (record.getType()) {
			case LmfConstants.LMF_HEADER_REC:
				throw new QnxException("Encountered a second LMF header");

			case LmfConstants.LMF_COMMENT_REC:
				Msg.debug(this, "Parsing record type: Comment");
				break;

			case LmfConstants.LMF_LOAD_REC:
				LmfLoadRecord rec = new LmfLoadRecord(reader, record);

				if (rec.getSegmentIndex() < 0 || header.getSegments().size() < rec.getSegmentIndex()) {
					throw new QnxException("Bad segment index on LOAD_REC");
				}

				// Get the segment that this data is to be loaded into
				LmfSegmentHeader segmentHeader = header.getSegments().get(rec.getSegmentIndex());
				segmentHeader.addDataBlock(rec);
				break;

			case LmfConstants.LMF_FIXUP_REC:
				Msg.debug(this, "Parsing record type: Fixup");
				
				// TODO: See https://github.com/open-watcom/open-watcom-v2/blob/master/bld/exedump/c/qnxexe.c#L190
				// `emu387` has a fixup table
				//int size = record.getDataNbytes();
				
				break;

			case LmfConstants.LMF_8087_FIXUP_REC:
				Msg.debug(this, "Parsing record type: 8087 Fixup");
				break;

			case LmfConstants.LMF_RESOURCE_REC:
				Msg.debug(this, "Parsing record type: Resource");
				LmfResource.createLmfResource(reader, record);
				break;

			case LmfConstants.LMF_RW_END_REC:
				verify = reader.readNextShort();
				signature = reader.readNextInt();
				break;

			case LmfConstants.LMF_LINEAR_FIXUP_REC:
				Msg.debug(this, "Parsing record type: Linear fixup");
				break;

			default:
				throw new QnxException("Unknown LMF record type: " + record.getType());
			}
		}
	}

	public LmfHeader getLmfHeader() {
		return header;
	}

	public short getVerify() {
		return verify;
	}

	public int getSignature() {
		return signature;
	}
}
