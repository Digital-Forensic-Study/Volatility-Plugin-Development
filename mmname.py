# Made by Sooboon on 25.05.05

import contextlib
import logging
import datetime
from typing import List

from volatility3.framework import exceptions, renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)

class Mmname(interfaces.plugins.PluginInterface):
    """Prints the memory map based on process name"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.StringRequirement(
                name="name",
                description="Name of the process to include",
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract listed memory segments",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="list",
                description="List matching processes without dumping memory map",
                default=False,
                optional=True,
            ),
            requirements.ListRequirement(
                name="select_pid",
                element_type=int,
                description="Specify one or more PIDs to include",
                optional=True,
            ),
        ]

    def _generator(self, procs):
        for proc in procs:
            pid = "Unknown"
            try:
                pid = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
                proc_layer = self.context.layers[proc_layer_name]
            except exceptions.InvalidAddressException as excp:
                vollog.debug(
                    f"Process {pid}: invalid address {excp.invalid_address} in layer {excp.layer_name}"
                )
                continue

            if self.config["dump"]:
                file_handle = self.open(f"pid.{pid}.dmp")
            else:
                file_handle = contextlib.ExitStack()

            with file_handle as file_data:
                file_offset = 0
                for mapval in proc_layer.mapping(
                    0x0, proc_layer.maximum_address, ignore_errors=True
                ):
                    offset, size, mapped_offset, mapped_size, maplayer = mapval

                    file_output = "Disabled"
                    if self.config["dump"]:
                        try:
                            data = proc_layer.read(offset, size, pad=True)
                            file_data.write(data)
                            file_output = file_handle.preferred_filename
                        except exceptions.InvalidAddressException:
                            file_output = "Error outputting to file"
                            vollog.debug(
                                f"Unable to write {proc_layer_name}'s address {offset} to {file_handle.preferred_filename}"
                            )

                    yield (
                        0,
                        (
                            format_hints.Hex(offset),
                            format_hints.Hex(mapped_offset),
                            format_hints.Hex(mapped_size),
                            format_hints.Hex(file_offset),
                            file_output,
                        ),
                    )

                    file_offset += mapped_size
                    offset += mapped_size

    def run(self):
        name_filter = self.config.get("name", "").lower()
        kernel = self.context.modules[self.config["kernel"]]

        all_procs = pslist.PsList.list_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
        )

        matched_procs = []
        for proc in all_procs:
            try:
                raw_name = bytes(proc.ImageFileName)
                decoded_name = raw_name.decode("utf-8", errors="ignore").strip("\x00")
                vollog.debug(f"[mmname] PID {proc.UniqueProcessId}: '{decoded_name}'")
                if name_filter in decoded_name.lower():
                    matched_procs.append(proc)
            except Exception as e:
                vollog.warning(f"[mmname] Could not decode process name: {e}")

        if not matched_procs:
            vollog.warning(f"[mmname] No processes found matching name: {self.config.get('name')}")
            if self.config.get("list", False):
                output_lines = [
                    f"--> [mmname] No processes found matching name '{self.config.get('name')}' please enter a different process\n"
                ]
                return renderers.TreeGrid(
                    [("Message", str)],
                    [(0, (line,)) for line in output_lines],
                )
            return renderers.TreeGrid(
                [("Message", str)],
                [(0, (f"[mmname] No processes found matching name: {self.config.get('name')}",))],
            )

        selected_pids = self.config.get("select_pid", [])

        if selected_pids:
            selected_proc_objs = [proc for proc in matched_procs if proc.UniqueProcessId in selected_pids]

            if not self.config.get("dump", False):
                if len(selected_proc_objs) > 1:
                    output_lines = ["--> [mmname] Only one process memory map can be printed. Please select only one process.\n"]
                    return renderers.TreeGrid(
                        [("Message", str)],
                        [(0, (line,)) for line in output_lines],
                    )
                elif len(selected_proc_objs) == 0:
                    output_lines = ["--> [mmname] No matching PID found in the process list.\n"]
                    return renderers.TreeGrid(
                        [("Message", str)],
                        [(0, (line,)) for line in output_lines],
                    )
            matched_procs = selected_proc_objs

        if self.config.get("list", False):
            output_lines = []
            output_lines.append(f"[mmname] Matching processes with name '{self.config.get('name')}':")
            output_lines.append("-" * 69)
            output_lines.append("ImageFileName       PID    CreateTime           ExitTime\n")

            for proc in matched_procs:
                pid = str(proc.UniqueProcessId)
                try:
                    raw_name = bytes(proc.ImageFileName)
                    decoded_name = raw_name.decode("utf-8", errors="ignore").strip("\x00")
                except Exception:
                    decoded_name = "Unknown"

                try:
                    create_time_obj = proc.get_create_time()
                    create_time = create_time_obj.strftime("%Y-%m-%d %H:%M:%S") if create_time_obj else "N/A"
                except Exception:
                    create_time = "N/A"

                try:
                    exit_time_obj = proc.get_exit_time()
                    if exit_time_obj and exit_time_obj.year > 1970:
                        exit_time = exit_time_obj.strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        exit_time = "Running"
                except Exception:
                    exit_time = "Running"

                output_lines.append(f"{decoded_name:<20}{pid:<7}{create_time:<21}{exit_time}")

            output_lines.append("-" * 69)
            output_lines.append("--> If there are multiple processes, Please re-run with --select-pid <PID> to proceed.\n")

            return renderers.TreeGrid(
                [("Message", str)],
                [(0, (line,)) for line in output_lines],
            )

        if not self.config.get("dump", False) and len(matched_procs) > 1:
            output_lines = []
            output_lines.append(f"[mmname] Matching processes with name '{self.config.get('name')}':")
            output_lines.append("+ Only one process memory map can be printed.")
            output_lines.append("-" * 69)
            output_lines.append("ImageFileName       PID    CreateTime           ExitTime\n")

            for proc in matched_procs:
                pid = str(proc.UniqueProcessId)
                try:
                    raw_name = bytes(proc.ImageFileName)
                    decoded_name = raw_name.decode("utf-8", errors="ignore").strip("\x00")
                except Exception:
                    decoded_name = "Unknown"

                try:
                    create_time_obj = proc.get_create_time()
                    create_time = create_time_obj.strftime("%Y-%m-%d %H:%M:%S") if create_time_obj else "N/A"
                except Exception:
                    create_time = "N/A"

                try:
                    exit_time_obj = proc.get_exit_time()
                    if exit_time_obj and exit_time_obj.year > 1970:
                        exit_time = exit_time_obj.strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        exit_time = "Running"
                except Exception:
                    exit_time = "Running"

                output_lines.append(f"{decoded_name:<20}{pid:<7}{create_time:<21}{exit_time}")

            output_lines.append("-" * 69)
            output_lines.append("--> If there are multiple processes, Please re-run with --select-pid <PID> to proceed.\n")

            return renderers.TreeGrid(
                [("Message", str)],
                [(0, (line,)) for line in output_lines],
            )

        return renderers.TreeGrid(
            [
                ("Virtual", format_hints.Hex),
                ("Physical", format_hints.Hex),
                ("Size", format_hints.Hex),
                ("Offset in File", format_hints.Hex),
                ("File output", str),
            ],
            self._generator(matched_procs),
        )