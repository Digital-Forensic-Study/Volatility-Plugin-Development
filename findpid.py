import datetime
from typing import Iterator

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist


class FindPid(interfaces.plugins.PluginInterface):
    """Find processes by partial name and show PID, Create/Exit time."""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel module",
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

        search_term = self.config["name"].lower()

        for proc in pslist.PsList.list_processes(
            context=self.context,
            layer_name=layer_name,
            symbol_table=symbol_table
        ):
            try:
                proc_name = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")
                if search_term in proc_name.lower():
                    pid = int(proc.UniqueProcessId)
                    create_time = proc.get_create_time().strftime("%Y-%m-%d %H:%M:%S")

                    exit_time_dt = proc.get_exit_time()
                    if exit_time_dt == datetime.datetime.fromtimestamp(0):
                        exit_time = "Running"
                    else:
                        exit_time = exit_time_dt.strftime("%Y-%m-%d %H:%M:%S")

                    yield (0, (proc_name, pid, create_time, exit_time))
            except Exception:
                continue

    def run(self):
        return renderers.TreeGrid(
            [
                ("Process Name", str),
                ("PID", int),
                ("Create Time", str),
                ("Exit Time", str),
            ],
            self._generator()
        )
