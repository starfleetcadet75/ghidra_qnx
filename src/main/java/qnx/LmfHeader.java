package qnx;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;

/**
 * A class to represent the lmf_header struct as defined in
 * <code>exeqnx.h</code>. <br>
 * 
 * <pre>
 * typedef struct lmf_header {
 *     unsigned_16     version;  
 *     unsigned_16     cflags;  
 *     unsigned_16     cpu;            // 86,186,286,386,486  
 *     unsigned_16     fpu;            // 0, 87,287,387  
 *     unsigned_16     code_index;     // segment of code start;  
 *     unsigned_16     stack_index;    // segment to put the stack  
 *     unsigned_16     heap_index;     // segment to start DS at.  
 *     unsigned_16     argv_index;     // segment to put argv & environment.  
 *     unsigned_16     spare2[4];      // must be zero;  
 *     unsigned_32     code_offset;    // starting offset of code.  
 *     unsigned_32     stack_nbytes;   // stack size  
 *     unsigned_32     heap_nbytes;    // initial size of heap (optional).  
 *     unsigned_32     image_base;     // starting address of image  
 *     unsigned_32     spare3[2];
 *     unsigned_32     seg_nbytes[1];  // variable length array of seg. sizes.
 * } lmf_header;
 * </pre>
 * 
 * @see <a href=
 *      "https://github.com/open-watcom/open-watcom-v2/blob/57ba42ef9e97d074577a3408bb8f28a586c902f7/bld/watcom/h/exeqnx.h#L83">watcom/h/exeqnx.h</a>
 */
public class LmfHeader {
	private int version;
	private int cflags;
	private int cpu;
	private int fpu;
	private int codeIndex;
	private int stackIndex;
	private int heapIndex;
	private int argvIndex;
	private long codeOffset;
	private long stackNbytes;
	private long heapNbytes;
	private long imageBase;
	private ArrayList<LmfSegmentHeader> segments;

	public static LmfHeader createLmfHeader(FactoryBundledWithBinaryReader reader, int nsegments)
			throws IOException, QnxException {
		LmfHeader lmfHeader = (LmfHeader) reader.getFactory().create(LmfHeader.class);
		lmfHeader.initLmfHeader(reader, nsegments);
		return lmfHeader;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS
	 * INSTEAD.
	 */
	public LmfHeader() {
	}

	private void initLmfHeader(FactoryBundledWithBinaryReader reader, int nsegments) throws IOException, QnxException {
		version = reader.readNextUnsignedShort();
		cflags = reader.readNextUnsignedShort();
		cpu = reader.readNextUnsignedShort();
		fpu = reader.readNextUnsignedShort();
		codeIndex = reader.readNextUnsignedShort();
		stackIndex = reader.readNextUnsignedShort();
		heapIndex = reader.readNextUnsignedShort();
		argvIndex = reader.readNextUnsignedShort();
		reader.readNextShortArray(4);
		codeOffset = reader.readNextUnsignedInt();
		stackNbytes = reader.readNextUnsignedInt();
		heapNbytes = reader.readNextUnsignedInt();
		imageBase = reader.readNextUnsignedInt();
		reader.readNextIntArray(2);

		// Create the segment headers
		segments = new ArrayList<LmfSegmentHeader>();

		for (int i = 0; i < nsegments; i++) {
			segments.add(new LmfSegmentHeader(reader));
		}

		String segmentName = "unk";
		int csegCount = 1;
		int dsegCount = 1;

		// Determine the names for each segment once they have all been created
		for (LmfSegmentHeader segment : segments) {
			if (segment.isCode()) {
				segmentName = String.format("cseg_%02d", csegCount);
				csegCount++;
			} else {
				segmentName = String.format("dseg_%02d", dsegCount);
				dsegCount++;
			}

			segment.setSegmentName(segmentName);
		}

		long startAddress = -1;

		// Determine the start address for each segment once they have all been created
		for (LmfSegmentHeader segment : segments) {
			if (startAddress == -1) {
				// The image base is always the start address for the first segment
				startAddress = imageBase;
			} else {
				// Align the start address based on page size
				long page_size = 0x1000;
				startAddress = (startAddress + page_size - 1) & ~(page_size - 1);
			}

			segment.setStartAddress(startAddress);

			// Set to the end of the segment so the next segment knows where to begin
			startAddress += segment.getSegmentSize();
		}
	}

	public void sortSegmentDataBlocks() {
		for (LmfSegmentHeader segment : segments) {
			segment.sortData();
		}
	}

	public String getDescription() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("version: 0x" + Integer.toHexString(version) + "\n");
		buffer.append("cflags: 0b" + Integer.toBinaryString(cflags) + "\n");
		buffer.append("cpu: " + cpu + "\n");
		buffer.append("fpu: " + fpu + "\n");
		buffer.append("code_index: " + codeIndex + "\n");
		buffer.append("stack_index: " + stackIndex + "\n");
		buffer.append("heap_index: " + heapIndex + "\n");
		buffer.append("argv_index: " + argvIndex + "\n");
		buffer.append("code_offset: " + Long.toHexString(codeOffset) + "\n");
		buffer.append("stack_nbytes: " + Long.toHexString(stackNbytes) + "\n");
		buffer.append("heap_nbytes: " + Long.toHexString(heapNbytes) + "\n");
		buffer.append("image_base: " + Long.toHexString(imageBase) + "\n");
		buffer.append("segments:\n");

		for (LmfSegmentHeader segment : segments) {
			buffer.append(segment.toString() + "\n");
		}

		return buffer.toString();
	}

	@Override
	public String toString() {
		return getDescription();
	}

	public int getVersion() {
		return version;
	}

	public int getCflags() {
		return cflags;
	}

	public int getCpu() {
		return cpu;
	}

	public int getFpu() {
		return fpu;
	}

	public int getCodeIndex() {
		return codeIndex;
	}

	public int getStackIndex() {
		return stackIndex;
	}

	public int getHeapIndex() {
		return heapIndex;
	}

	public int getArgvIndex() {
		return argvIndex;
	}

	public long getCodeOffset() {
		return codeOffset;
	}

	public long getStackNbytes() {
		return stackNbytes;
	}

	public long getHeapNbytes() {
		return heapNbytes;
	}

	/**
	 * This member gives the base address for loading the program.
	 * 
	 * @return the base address for the program
	 */
	public long getImageBase() {
		return imageBase;
	}

	public ArrayList<LmfSegmentHeader> getSegments() {
		return segments;
	}
}
