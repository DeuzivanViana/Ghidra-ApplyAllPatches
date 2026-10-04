#@category Patching
#@runtime Jython

import hashlib
import os
import shutil
import stat
import tempfile

from java.io import File
from ghidra.app.util.exporter import OriginalFileExporter


CHUNK_SIZE = 65536

try:
	text_type = unicode
except NameError:
	text_type = str


def digest_file(stream, task_monitor=None):
	stream.seek(0)
	result = hashlib.sha256()
	while True:
		if task_monitor is not None:
			task_monitor.checkCancelled()
		data = stream.read(CHUNK_SIZE)
		if not data:
			return result.hexdigest()
		result.update(data)


def file_size(stream):
	stream.seek(0, os.SEEK_END)
	return stream.tell()


def file_identity(path):
	info = os.lstat(path)
	if not stat.S_ISREG(info.st_mode):
		raise ValueError("The target must remain a regular file, not a symbolic link.")
	return info.st_dev, info.st_ino


def require_identity(path, expected_identity):
	if file_identity(path) != expected_identity:
		raise IOError("The target file was replaced. No further patches will be written.")


def collect_changes(target_path, desired_path, task_monitor):
	changes = []
	old_hash = hashlib.sha256()
	new_hash = hashlib.sha256()
	changed_bytes = 0
	offset = 0
	identity = file_identity(target_path)
	total = os.path.getsize(target_path)
	if total != os.path.getsize(desired_path):
		raise ValueError("File sizes differ. The executable has not been modified.")
	task_monitor.initialize(total)
	task_monitor.setMessage("Comparing all bytes...")
	with open(target_path, "rb") as old_file, open(desired_path, "rb") as new_file:
		while True:
			task_monitor.checkCancelled()
			old = old_file.read(CHUNK_SIZE)
			new = new_file.read(CHUNK_SIZE)
			if len(old) != len(new):
				raise ValueError("A file changed while it was being read.")
			if not old:
				break
			old_hash.update(old)
			new_hash.update(new)
			if old != new:
				position = 0
				while position < len(old):
					if old[position] == new[position]:
						position += 1
						continue
					start = position
					while position < len(old) and old[position] != new[position]:
						position += 1
					changes.append((offset + start, old[start:position], new[start:position]))
					changed_bytes += position - start
			offset += len(old)
			task_monitor.setProgress(offset)
	require_identity(target_path, identity)
	if offset != total:
		raise ValueError("The target size changed during comparison.")
	return changes, changed_bytes, old_hash.hexdigest(), new_hash.hexdigest(), total, identity


def create_verified_backup(target_path, target, old_digest, size, task_monitor):
	task_monitor.setMessage("Creating a new verified backup...")
	descriptor, backup_path = tempfile.mkstemp(
		prefix=os.path.basename(target_path) + ".ghidra-", suffix=".bak",
		dir=os.path.dirname(target_path))
	try:
		output = os.fdopen(descriptor, "wb")
		descriptor = None
		with output:
			target.seek(0)
			copied_digest = hashlib.sha256()
			copied_size = 0
			while True:
				task_monitor.checkCancelled()
				data = target.read(CHUNK_SIZE)
				if not data:
					break
				output.write(data)
				copied_digest.update(data)
				copied_size += len(data)
			output.flush()
			os.fsync(output.fileno())
		if copied_size != size or copied_digest.hexdigest() != old_digest:
			raise IOError("The target changed during backup. No patches were written.")
		with open(backup_path, "rb") as backup:
			if file_size(backup) != size or digest_file(backup, task_monitor) != old_digest:
				raise IOError("Backup verification failed. No patches were written.")
		os.chmod(backup_path, stat.S_IMODE(os.stat(target_path).st_mode) & 0o777)
		return backup_path
	except:
		if descriptor is not None:
			os.close(descriptor)
		try:
			os.remove(backup_path)
		except OSError:
			pass
		raise


def apply_changes(target_path, changes, old_digest, new_digest, size, identity, task_monitor):
	require_identity(target_path, identity)
	try:
		target = open(target_path, "r+b")
	except (IOError, OSError) as error:
		raise IOError("Cannot open the executable for writing. Stop its running process "
					  "and check file permissions. Details: " + text_type(error))
	with target:
		require_identity(target_path, identity)
		if file_size(target) != size or digest_file(target, task_monitor) != old_digest:
			raise ValueError("The executable changed after comparison. Run the script again.")
		task_monitor.checkCancelled()
		backup_path = create_verified_backup(target_path, target, old_digest, size, task_monitor)
		require_identity(target_path, identity)
		if file_size(target) != size or digest_file(target, task_monitor) != old_digest:
			raise ValueError("The executable changed during backup. No patches were written.")
		task_monitor.initialize(len(changes))
		task_monitor.setMessage("Applying modified byte ranges...")
		attempted = 0
		try:
			for offset, old, new in changes:
				task_monitor.checkCancelled()
				require_identity(target_path, identity)
				target.seek(offset)
				if target.read(len(old)) != old:
					raise IOError("The target bytes changed before a patch was written.")
				target.seek(offset)
				attempted += 1
				target.write(new)
				task_monitor.setProgress(attempted)
			target.flush()
			os.fsync(target.fileno())
			require_identity(target_path, identity)
			if file_size(target) != size or digest_file(target, task_monitor) != new_digest:
				raise IOError("Verification of the patched executable failed.")
		except:
			try:
				for offset, old, new in reversed(changes[:attempted]):
					target.seek(offset)
					target.write(old)
				target.flush()
				os.fsync(target.fileno())
				if file_size(target) != size or digest_file(target) != old_digest:
					raise IOError("Rollback verification failed.")
			except:
				raise IOError("Patch/rollback failed. Recover using the verified backup: " + backup_path)
			raise
	return backup_path


def main():
	if currentProgram is None:
		raise ValueError("Open the program in the Static Listing first.")

	sources = currentProgram.getMemory().getAllFileBytes()
	if sources.size() != 1 or sources.get(0).getFileOffset() != 0:
		raise ValueError("This script requires one executable imported directly from a file.")

	target_file = File(currentProgram.getExecutablePath()).getCanonicalFile()
	if not target_file.isFile():
		target_file = askFile("Select the existing executable", "Use file").getCanonicalFile()
	if not target_file.isFile():
		raise ValueError("The target must be an existing regular file.")
	if target_file.length() != sources.get(0).getSize():
		raise ValueError("The target size differs from the imported file. Operation cancelled.")
	target_path = text_type(target_file.getPath())

	temporary_directory = tempfile.mkdtemp(prefix="ghidra-all-patches-")
	temporary_path = os.path.join(temporary_directory, "exported.bin")
	try:
		monitor.setMessage("Preparing all patches with Original File...")
		exporter = OriginalFileExporter()
		if not exporter.export(File(temporary_path), currentProgram, None, monitor):
			raise IOError("Original File could not export this program: " +
						  text_type(exporter.getMessageLog()))
		monitor.checkCancelled()
		changes, count, old_digest, new_digest, size, identity = collect_changes(
			target_path, temporary_path, monitor)
		if not changes:
			println("No differences: the executable already matches the exportable Static bytes.")
			return

		println("Target: " + target_path)
		println("Changes: %d bytes in %d ranges." % (count, len(changes)))
		prompt = (
			u"Apply %d bytes in %d ranges?\n\n%s\n\n"
			u"Stop the debugged process and other file writers before continuing.\n"
			u"A new verified .bak file will be created beside the executable.\n\n"
			u"The file will match the current Original File export, including its limitations.\n"
			u"Any existing differences outside Ghidra will also be overwritten."
		) % (count, len(changes), target_path)
		if not askYesNo("Apply all patches", prompt):
			println("Cancelled. The executable has not been modified.")
			return

		backup_path = apply_changes(
			target_path, changes, old_digest, new_digest, size, identity, monitor)
		println("Done: %d bytes applied and verified." % count)
		println("Verified backup: " + backup_path)
		println("Start a new debugging session using this executable.")
	finally:
		try:
			shutil.rmtree(temporary_directory)
		except OSError as error:
			printerr("Could not remove temporary export directory: " + text_type(error))


if __name__ == "__main__":
	main()
