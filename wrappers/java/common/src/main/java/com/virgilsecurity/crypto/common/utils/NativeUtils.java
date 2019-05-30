package com.virgilsecurity.crypto.common.utils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.ProviderNotFoundException;
import java.nio.file.StandardCopyOption;
import java.util.logging.Level;
import java.util.logging.Logger;

public class NativeUtils {

	private static final String MACOS_OS_NAME = "mac os";
	private static final String LINUX_OS_NAME = "linux";
	private static final String WINDOWS_OS_NAME = "windows";
	private static final String UNKNOWN_OS = "unknown";

	private static final String MACOS_LIBS_DIRECTORY = "macos";
	private static final String LINUX_LIBS_DIRECTORY = LINUX_OS_NAME;
	private static final String WINDOWS_LIBS_DIRECTORY = WINDOWS_OS_NAME;

	private static final Logger LOG = Logger.getLogger("NativeUtils");

	public static void load(String name) {
		try {
			LOG.log(Level.WARNING, "Loading \"{0}\" library", name);
			NativeUtils.loadLibrary(name);
		} catch (IOException e) {
			LOG.log(Level.SEVERE, "Native library can't be loaded.", e);
		}
	}

	/**
	 * The minimum length a prefix for a file has to have according to
	 * {@link File#createTempFile(String, String)}}.
	 */
	private static final int MIN_PREFIX_LENGTH = 3;
	public static final String NATIVE_FOLDER_PATH_PREFIX = "nativeutils";

	/**
	 * Temporary directory which will contain the DLLs.
	 */
	private static File temporaryDir;

	/**
	 * Private constructor - this class will never be instanced
	 */
	private NativeUtils() {
	}

	public static void loadLibrary(String name) throws IOException {
		try {
			System.loadLibrary(name);
			// Library is loaded (Android or exists in java.library.path). We can exit
			return;
		} catch (Throwable e) {
			// Library couldn't be loaded yet. We'll load it later.
		}
		// Build native library name according to current system
		String osName = System.getProperty("os.name").toLowerCase();
		String os = getOS(osName);
		String osArch = System.getProperty("os.arch").toLowerCase();

		StringBuilder resourceName = new StringBuilder();
		resourceName.append(getResourceDirectory(os, osArch)).append(getLibraryFileName(os, name))
				.append(getLibraryFileSuffix(os));
		loadLibraryFromJar(resourceName.toString());
	}

	private static final String getLibraryFileSuffix(String os) {
		switch (os) {
		case LINUX_OS_NAME:
		case MACOS_OS_NAME:
			return ".so";
		case WINDOWS_OS_NAME:
			return ".dll";
		}
		return "";
	}

	/**
	 * Get operation system by operation system name
	 *
	 * @param osName The OS name.
	 * @return
	 */
	private static final String getOS(String osName) {
		for (String os : new String[] { LINUX_OS_NAME, WINDOWS_OS_NAME, MACOS_OS_NAME }) {
			if (osName.startsWith(os)) {
				return os;
			}
		}
		return UNKNOWN_OS;
	}

	private static final String getResourceDirectory(String os, String osArch) {
		StringBuilder sb = new StringBuilder("/");
		switch (os) {
		case LINUX_OS_NAME:
			sb.append(LINUX_LIBS_DIRECTORY);
			break;
		case MACOS_OS_NAME:
			sb.append(MACOS_LIBS_DIRECTORY);
			break;
		case WINDOWS_OS_NAME:
			sb.append(WINDOWS_LIBS_DIRECTORY);
			break;
		}
		return sb.append("/").toString();
	}

	private static final String getLibraryFileName(String os, String libName) {
		StringBuilder sb = new StringBuilder();
		switch (os) {
		case LINUX_OS_NAME:
		case MACOS_OS_NAME:
			sb.append("lib").append(libName);
			break;
		case WINDOWS_OS_NAME:
			sb.append(libName);
			break;
		}
		return sb.append("_java").toString();
	}

	/**
	 * Loads library from current JAR archive
	 *
	 * The file from JAR is copied into system temporary directory and then loaded.
	 * The temporary file is deleted after exiting. Method uses String as filename
	 * because the pathname is "abstract", not system-dependent.
	 *
	 * @param path The path of file inside JAR as absolute path (beginning with
	 *             '/'), e.g. /package/File.ext
	 * @throws IOException              If temporary file creation or read/write
	 *                                  operation fails
	 * @throws IllegalArgumentException If source file (param path) does not exist
	 * @throws IllegalArgumentException If the path is not absolute or if the
	 *                                  filename is shorter than three characters
	 *                                  (restriction of
	 *                                  {@link File#createTempFile(java.lang.String, java.lang.String)}).
	 * @throws FileNotFoundException    If the file could not be found inside the
	 *                                  JAR.
	 */
	public static void loadLibraryFromJar(String path) throws IOException {

		if (null == path || !path.startsWith("/")) {
			throw new IllegalArgumentException("The path has to be absolute (start with '/').");
		}

		// Obtain filename from path
		String[] parts = path.split("/");
		String filename = (parts.length > 1) ? parts[parts.length - 1] : null;

		// Check if the filename is okay
		if (filename == null || filename.length() < MIN_PREFIX_LENGTH) {
			throw new IllegalArgumentException("The filename has to be at least 3 characters long.");
		}

		// Prepare temporary file
		if (temporaryDir == null) {
			temporaryDir = createTempDirectory(NATIVE_FOLDER_PATH_PREFIX);
			temporaryDir.deleteOnExit();
		}

		File temp = new File(temporaryDir, filename);

		try (InputStream is = NativeUtils.class.getResourceAsStream(path)) {
			Files.copy(is, temp.toPath(), StandardCopyOption.REPLACE_EXISTING);
		} catch (IOException e) {
			temp.delete();
			throw e;
		} catch (NullPointerException e) {
			temp.delete();
			throw new FileNotFoundException("File " + path + " was not found inside JAR.");
		}

		try {
			System.load(temp.getAbsolutePath());
		} finally {
			if (isPosixCompliant()) {
				// Assume POSIX compliant file system, can be deleted after loading
				temp.delete();
			} else {
				// Assume non-POSIX, and don't delete until last file descriptor closed
				temp.deleteOnExit();
			}
		}
	}

	private static boolean isPosixCompliant() {
		try {
			return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
		} catch (FileSystemNotFoundException | ProviderNotFoundException | SecurityException e) {
			return false;
		}
	}

	private static File createTempDirectory(String prefix) throws IOException {
		String tempDir = System.getProperty("java.io.tmpdir");
		File generatedDir = new File(tempDir, prefix + System.nanoTime());

		if (!generatedDir.mkdir())
			throw new IOException("Failed to create temp directory " + generatedDir.getName());

		return generatedDir;
	}

}
