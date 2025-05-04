import datetime
import logging
from typing import Iterator

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class FindPid(interfaces.plugins.PluginInterface):
    """Finds processes by partial name and shows PID, Create/Exit time."""

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
            filter_func=lambda _: False  # 전체 출력
        ):
            try:
                proc_name = utility.array_to_string(proc.ImageFileName)
                if keyword not in proc_name.lower():
                    continue  # 필터 통과 못 하면 제외

                pid = int(proc.UniqueProcessId)
                create_time = proc.get_create_time()

                exit_time_dt = proc.get_exit_time()
                if exit_time_dt == datetime.datetime.fromtimestamp(0):
                    exit_time = "Running"
                else:
                    exit_time = exit_time_dt.strftime("%Y-%m-%d %H:%M:%S")

                yield (0, (
                    proc_name,
                    pid,
                    create_time.strftime("%Y-%m-%d %H:%M:%S"),
                    exit_time
                ))

            except exceptions.InvalidAddressException:
                vollog.debug(f"Invalid process at: {proc.vol.offset:#x}, skipping.")
            except Exception as e:
                vollog.debug(f"Error in process at {proc.vol.offset:#x}: {e}")

    def run(self):
        return renderers.TreeGrid(
            [
                ("ImageFileName", str),
                ("PID", int),
                ("CreateTime", str),
                ("ExitTime", str),
            ],
            self._generator()
        )
