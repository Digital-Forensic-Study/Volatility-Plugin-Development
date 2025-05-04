# 설명

import datetime
import logging
from typing import Iterator

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class FindPid(interfaces.plugins.PluginInterface):
    """Finds processes whose names contain a given substring and shows their PID and times."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"]
            ),
            requirements.StringRequirement(
                name="name",
                description="Partial name of the process to search for",
                optional=False
            ),
        ]

    def _generator(self) -> Iterator:
        kernel = self.context.modules[self.config["kernel"]]
        layer_name = kernel.layer_name
        symbol_table = kernel.symbol_table_name

        keyword = self.config["name"].lower()

        for proc in pslist.PsList.list_processes(
            context=self.context,
            layer_name=layer_name,
            symbol_table=symbol_table,
            filter_func=lambda _: False
        ):
            try:
                proc_name = utility.array_to_string(proc.ImageFileName)
                if keyword not in proc_name.lower():
                    continue

                pid = int(proc.UniqueProcessId)
                create_time = proc.get_create_time()

                try:
                    exit_time_obj = proc.get_exit_time()
                    if exit_time_obj and exit_time_obj.year > 1970:
                        exit_time = exit_time_obj.strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        exit_time = "Running"
                except Exception:
                    exit_time = "Running"

                yield (0, (
                    proc_name,
                    pid,
                    create_time.strftime("%Y-%m-%d %H:%M:%S"),
                    exit_time
                ))

            except exceptions.InvalidAddressException:
                vollog.debug(f"Invalid process at: {proc.vol.offset:#x}, skipping.")
            except Exception as e:
                vollog.debug(f"Error reading process at {proc.vol.offset:#x}: {e}")

    def run(self):
        return renderers.TreeGrid(
            [
                ("ImageFileName", str),
                ("PID", int),
                ("CreateTime", str),
                ("ExitTime", str),
            ],
            self._generator(),
        )
