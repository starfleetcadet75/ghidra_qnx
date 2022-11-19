package qnx;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;

public class LmfSegmentHeader {
	private String segmentName;
	private int segmentType;
	private int segmentSize;
	private boolean isCode;
	private boolean isReadable;
	private boolean isWritable;
	private boolean isExecutable;
	private long startAddress;
	private ArrayList<LmfLoadRecord> dataBlocks;

	public LmfSegmentHeader(BinaryReader reader) throws IOException, QnxException {
		dataBlocks = new ArrayList<LmfLoadRecord>();

		int segment = reader.readNextInt();
		segmentType = segment >> 28;  // Uppermost byte indicates the type of this segment
		segmentSize = segment & 0x0fff_ffff;  // Segment size is the lower 7 bytes

		if (segmentType == 0) {
			isCode = false;
			isReadable = true;
			isWritable = true;
			isExecutable = false;
		} else if (segmentType == 1) {
			isCode = false;
			isReadable = true;
			isWritable = false;
			isExecutable = false;
		} else if (segmentType == 2) {
			isCode = true;
			isReadable = true;
			isWritable = false;
			isExecutable = true;
		} else if (segmentType == 3) {
			isCode = true;
			isReadable = false;
			isWritable = false;
			isExecutable = true;
		} else {
			throw new QnxException("Unknown segment type: " + segmentType);
		}

		// Will be set by the LmfHeader
		startAddress = -1;
	}

	public void addDataBlock(LmfLoadRecord rec) {
		dataBlocks.add(rec);
	}

	/**
	 * Sort the data-blocks within this segment
	 */
	protected void sortData() {
		Collections.sort(dataBlocks);
	}

	/**
	 * Get an InputStream that reads in the raw data for this segment
	 * 
	 * @param reader is the image file reader
	 * @param log    the log
	 * @return the InputStream
	 * @throws IOException for problems reading from the image file
	 */
	public InputStream getRawDataStream(BinaryReader reader, MessageLog log) throws IOException {
		return new SectionStream(reader, log);
	}

	public void setSegmentName(String segmentName) {
		this.segmentName = segmentName;
	}

	public String getSegmentName() {
		return segmentName;
	}

	public int getSegmentType() {
		return segmentType;
	}

	public int getSegmentSize() {
		return segmentSize;
	}

	/**
	 * @return true if this is a code segment
	 */
	public boolean isCode() {
		return isCode;
	}

	/**
	 * @return true if this segment is readable
	 */
	public boolean isReadable() {
		return isReadable;
	}

	/**
	 * @return true if this segment is writable
	 */
	public boolean isWritable() {
		return isWritable;
	}

	/**
	 * @return true if this segment is executable
	 */
	public boolean isExecutable() {
		return isExecutable;
	}

	public void setStartAddress(long startAddress) {
		this.startAddress = startAddress;
	}

	/**
	 * @return the load image address for this segment
	 */
	public long getStartAddress() {
		return startAddress;
	}

	/**
	 * @param language is the Program language for this binary
	 * @return the starting Address for this segment
	 */
	public Address getAddress(Language language) {
		AddressSpace addrSpace;

		if (isCode) {
			addrSpace = language.getDefaultSpace();
		} else {
			addrSpace = language.getDefaultDataSpace();
		}

		return addrSpace.getAddress(startAddress);
	}

	public String getDescription() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("segment name: " + segmentName + "\n");
		buffer.append("type: " + segmentType + "\n");
		buffer.append("size: " + Integer.toHexString(segmentSize) + "\n");
		buffer.append("start address: " + Long.toHexString(startAddress) + "\n");
		return buffer.toString();
	}

	@Override
	public String toString() {
		return getDescription();
	}

	public class SectionStream extends InputStream {
		/**
		 * Maximum zero bytes added to pad initialized segments
		 */
		public final static long MAX_UNINITIALIZED_FILL = 0x2000;

		private BinaryReader reader;
		private MessageLog log;
		private long pointer; // Overall position within segment, relative to starting address
		private byte[] buffer; // Current buffer
		private int bufferpointer; // current index into buffer
		private int dataUpNext; // Index of next data section OmfIteratedData/OmfEnumeratedData to be buffered

		public SectionStream(BinaryReader reader, MessageLog log) throws IOException {
			super();

			this.reader = reader;
			this.log = log;
			pointer = 0;
			dataUpNext = 0;

			if (pointer < segmentSize) {
				establishNextBuffer();
			}
		}

		/**
		 * Fill the next buffer of bytes being provided by this stream.
		 * 
		 * @throws IOException for problems with the file image reader
		 */
		private void establishNextBuffer() throws IOException {
			while (dataUpNext < dataBlocks.size()) {
				LmfLoadRecord data = dataBlocks.get(dataUpNext);

				if (pointer < data.getVirtAddr()) {
					// We have some fill to produce before the next section
					long size = data.getVirtAddr() - pointer;
					if (MAX_UNINITIALIZED_FILL < size) {
						throw new IOException("Unfilled hole in data blocks for segment: " + segmentName);
					}

					buffer = new byte[(int) size];

					for (int i = 0; i < size; i++) {
						buffer[i] = 0;
					}

					bufferpointer = 0;
					return;
				} else if (pointer == data.getVirtAddr()) {
					buffer = data.getByteArray(reader);
					bufferpointer = 0;
					dataUpNext++;

					if (buffer.length == 0) {
						continue;
					}

					return;
				} else {
					dataUpNext++;
					throw new IOException(
							String.format("Segment %s has bad data offset (0x%x) in data block %d...skipping.",
									segmentName, data.getVirtAddr(), dataUpNext - 1));
				}
			}

			// TODO: Ensure that the warning here showing up in netinfo and others isn't an issue...
			
			// There may be filler required after the last block
			long size = segmentSize - pointer;
			if (MAX_UNINITIALIZED_FILL < size) {
				throw new IOException("Large hole at the end of segment: " + segmentName);
			}

			buffer = new byte[(int) size];
			for (int i = 0; i < size; i++) {
				buffer[i] = 0;
			}

			bufferpointer = 0;
		}

		@Override
		public int read() throws IOException {
			if (pointer < segmentSize) {
				if (bufferpointer < buffer.length) {
					pointer++;
					return buffer[bufferpointer++] & 0xff;
				}

				try {
					establishNextBuffer();
					pointer++;
					return buffer[bufferpointer++] & 0xff;
				} catch (IOException ex) {
					log.appendMsg(ex.getMessage());
				}
			}
			return -1;
		}
	}
}
