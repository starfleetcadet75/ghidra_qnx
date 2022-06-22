package qnx;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;

public class LmfLoadRecord implements Comparable<LmfLoadRecord> {
	/**
	 * Indicates the segment that this loadable record belongs in
	 */
	private short segmentIndex;
	/**
	 * Position in the loaded segment where the data should be placed
	 */
	private long virtAddr;
	/**
	 * Position in the input stream where the data starts
	 */
	private long physAddr;
	/**
	 * Size of the data not counting the size of the record metadata
	 */
	private int size;

	LmfLoadRecord(FactoryBundledWithBinaryReader reader, LmfRecord record) throws IOException {
		segmentIndex = reader.readNextShort();
		virtAddr = reader.readNextInt();
		physAddr = reader.getPointerIndex();
		size = record.getDataNbytes() - LmfConstants.LMF_DATA_SIZE;

		// Jump the reader past the LOAD content to the start of the next record
		reader.setPointerIndex(physAddr + size);
	}

	public short getSegmentIndex() {
		return segmentIndex;
	}

	public long getVirtAddr() {
		return virtAddr;
	}

	public long getPhysAddr() {
		return physAddr;
	}

	public int getSize() {
		return size;
	}

	@Override
	public int compareTo(LmfLoadRecord other) {
		long otherOffset = other.getVirtAddr();
		if (otherOffset == virtAddr) {
			return 0;
		}
		return (virtAddr < otherOffset) ? -1 : 1;
	}

	public byte[] getByteArray(BinaryReader reader) throws IOException {
		reader.setPointerIndex(physAddr);
		byte[] buffer = reader.readNextByteArray(size);
		return buffer;
	}

	public String getDescription() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("Segment Index: " + segmentIndex + "\n");
		buffer.append("Virtual Address: 0x" + Long.toHexString(virtAddr) + "\n");
		buffer.append("Physical Address: 0x" + Long.toHexString(physAddr) + "\n");
		buffer.append("Size: " + Integer.toHexString(size) + "\n");
		return buffer.toString();
	}

	@Override
	public String toString() {
		return getDescription();
	}
}
