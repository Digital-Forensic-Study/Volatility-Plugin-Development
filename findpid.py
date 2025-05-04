from typing import Iterator
import datetime

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist


class FindPid(interfaces.plugins.PluginInterface):
    """Find PID by partial process name using pslist."""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel module",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.StringRequirement(
                name="name",
                description="Partial name of the process to search for",
                optional=False,
            ),
        ]

    def _generator(self) -> Iterator:
        kernel = self.context.modules[self.config["kernel"]]
        layer_name = kernel.layer_name
        symbol_table = kernel.symbol_table_name

        search_term = self.config["name"].lower()

        for proc in pslist.PsList.list_processes(
            context=self.context,
            layer_name=layer_name,
            symbol_table=symbol_table,
            filter_func=lambda _: False
        ):
            try:
                name = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")
                if search_term in name.lower():
                    create_time = proc.get_create_time()
                    exit_time = proc.get_exit_time()
                    yield (0, (name, int(proc.UniqueProcessId), create_time, exit_time))
            except Exception:
                pass

    def run(self):
        return renderers.TreeGrid(
            [
                ("Process Name", str),
                ("PID", int),
                ("Create Time", datetime.datetime),
                ("Exit Time", datetime.datetime)
            ],
            self._generator()
        )
