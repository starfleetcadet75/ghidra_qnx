package qnx;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.options.Options;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * QNX Executable Format loader.
 */
public class QnxLoader extends AbstractProgramWrapperLoader {
	/**
	 * The name of the QNX loader.
	 */
	public final static String QNX_NAME = "QNX Executable Format (LMF)";

	/**
	 * The minimum length a file has to be for it to qualify as a possible QNX file.
	 */
	private static final long MIN_BYTE_LENGTH = 6;

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() < MIN_BYTE_LENGTH) {
			return loadSpecs;
		}

		try {
			QnxExecutable qnx = new QnxExecutable(provider);
			LmfHeader header = qnx.getLmfHeader();
			if (header != null) {
				long imageBase = header.getImageBase();

				// QNX programs are either 32 or 16-bit x86 little-endian
				loadSpecs.add(
						new LoadSpec(this, imageBase, new LanguageCompilerSpecPair("x86:LE:32:default", "gcc"), true));
				loadSpecs.add(new LoadSpec(this, imageBase,
						new LanguageCompilerSpecPair("x86:LE:16:Protected Mode", "default"), true));
			}
		} catch (QnxException ex) {
			// its not a QNX file
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		monitor.setMessage("Running the QNX loader");

		int id = program.startTransaction("Loading QNX program");
		boolean success = false;

		try {
			QnxExecutable qnx = new QnxExecutable(provider);
			LmfHeader lmfHeader = qnx.getLmfHeader();
			Msg.debug(this, "QNX EXE Header\n" + lmfHeader.toString());

			qnx.parse();
			lmfHeader.sortSegmentDataBlocks();

			monitor.setMessage("Completed QNX header parsing...");

			processSegments(provider, lmfHeader, program, monitor, log);
			// processFixups();
			processEntryPoints(lmfHeader, program, monitor, log);

			Options props = program.getOptions(Program.PROGRAM_INFO);
			props.setString("QNX Original Image Base", "0x" + Long.toHexString(lmfHeader.getImageBase()));
			props.setString("QNX Verify", "0x" + Integer.toHexString(qnx.getVerify()));
			props.setString("QNX Signature", "0x" + Integer.toHexString(qnx.getSignature()));

			success = true;
		} catch (QnxException | AddressOverflowException ex) {
			throw new IOException(ex);
		} finally {
			program.endTransaction(id, success);
		}

		monitor.setMessage("[" + program.getName() + "]: done!");
	}

	private void processSegments(ByteProvider provider, LmfHeader lmfHeader, Program program, TaskMonitor monitor,
			MessageLog log) throws AddressOverflowException, IOException {
		monitor.setMessage("[" + program.getName() + "]: processing segments...");

		// Create the segments based on the segments list from the LmfHeader
		ArrayList<LmfSegmentHeader> segments = lmfHeader.getSegments();
		BinaryReader reader = new BinaryReader(provider, true);

		for (LmfSegmentHeader segment : segments) {
			if (monitor.isCancelled()) {
				return;
			}

			Address segmentAddress = segment.getAddress(program.getLanguage());
			int segmentSize = segment.getSegmentSize();

			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false, segment.getSegmentName(),
					segmentAddress, segment.getRawDataStream(reader, log), segmentSize,
					"Address:0x" + Long.toHexString(segmentAddress.getOffset()) + " " + "Size:0x"
							+ Long.toHexString(segmentSize),
					null, segment.isReadable(), segment.isWritable(), segment.isExecutable(), log, monitor);

			if (block != null) {
				log.appendMsg("Created Initialized Block: " + segment.getSegmentName() + " @ " + segmentAddress);
			}
		}
	}

	private void processEntryPoints(LmfHeader lmfHeader, Program program, TaskMonitor monitor, MessageLog log) {
		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("[" + program.getName() + "]: processing entry points...");

		AddressFactory af = program.getAddressFactory();
		AddressSpace space = af.getDefaultAddressSpace();
		SymbolTable symTable = program.getSymbolTable();

		Address entryPoint = space.getAddress(lmfHeader.getImageBase() + lmfHeader.getCodeOffset());

		try {
			FunctionManager functionMgr = program.getFunctionManager();
			Function function = functionMgr.getFunctionAt(entryPoint);

			if (function == null) {
				function = functionMgr.createFunction(null, entryPoint, new AddressSet(entryPoint),
						SourceType.IMPORTED);
			}

			symTable.createLabel(entryPoint, "entry", SourceType.IMPORTED);
		} catch (InvalidInputException | OverlappingFunctionException ex) {
			log.appendMsg("Error while creating function at " + entryPoint + ": " + ex.getMessage());
		}

		symTable.addExternalEntryPoint(entryPoint);
	}

	@Override
	public String getName() {
		return QNX_NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.GENERIC_TARGET_LOADER;
	}
}
