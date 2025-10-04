# moonraker/components/gcode_preprocessor.py

import os
import asyncio
import logging

from moonraker.confighelper import ConfigHelper

# Create a module-level logger
LOG = logging.getLogger(__name__)

class GCodePreprocessorComponent:
    def __init__(self, config: ConfigHelper):
        server = config.get_server()

        # Core components
        fm    = server.lookup_component("file_manager")
        ms    = fm.get_metadata_storage()
        kapis = server.lookup_component("klippy_apis")

        # Read our Rust binary path
        self.binary = config.get("binary", None)
        if not self.binary:
            raise server.error("gcode_preprocessor: missing 'binary' setting")

        # Wrap metadata extraction (upload-time)
        orig_run = ms._run_extract_metadata
        async def run_and_extract(filename: str, ufp_path: str | None) -> None:
            await self._invoke_preprocessor(ms.gc_path, filename)
            return await orig_run(filename, ufp_path)
        ms._run_extract_metadata = run_and_extract

        # Wrap start_print (print-time)
        orig_start = kapis.start_print
        async def preprocess_and_print(filename: str, user=None):
            await self._invoke_preprocessor(ms.gc_path, filename)
            return await orig_start(filename, user=user)
        kapis.start_print = preprocess_and_print

    async def _invoke_preprocessor(self, gc_path: str, filename: str):
        """
        Call the Rust binary on the uploaded G-code file,
        await its completion, log its output, and error out on failure.
        """
        file_path = os.path.join(gc_path, filename)

        proc = await asyncio.create_subprocess_exec(
            self.binary, file_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            LOG.error(
                "[gcode_preprocessor] '%s' failed (exit %d):\n%s",
                self.binary, proc.returncode,
                stderr.decode(errors="ignore")
            )
            # Raise to abort metadata extraction (and the print-start hook)
            raise Exception(f"Preprocessor exited {proc.returncode}")

        # Log any summary your Rust tool printed
        summary = stdout.decode(errors="ignore").strip()
        if summary:
            LOG.info("[gcode_preprocessor] %s", summary)

def load_component(config: ConfigHelper):
    return GCodePreprocessorComponent(config)
