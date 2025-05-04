import datetime
import logging
from typing import Callable, Iterator

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
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

    @classmethod
    def create_name_filter(
        cls, keyword: str
    ) -> Callable[[interfaces.objects.ObjectInterface], bool]:
        """Returns a filter function that filters out processes that do NOT match."""
        lowered = keyword.lower()

        def filter_func(proc: interfaces.objects.ObjectInterface) -> bool:
            try:
                name = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")
                return lowered not in name.lower()  # False일 때 통과
            except Exception:
                return True  # 오류나면 제외

        return filter_func

    def _generator(self) -> Iterator:
        kernel = self.context.modules[self.config["kernel"]]
        layer_name = kernel.layer_name
        symbol_table = kernel.symbol_table_name

        filter_func = self.create_name_filter(self.config["name"])

        for proc in pslist.PsList.list_processes(
            context=self.context,
            layer_name=layer_name,
            symbol_table=symbol_table,
            filter_func=filter_func
        ):
            try:
                proc_name = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")
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
                vollog.debug(f"Invalid process found at: {proc.vol.offset:#x}. Skipping.")
            except Exception as e:
                vollog.debug(f"Error processing process at: {proc.vol.offset:#x}: {e}")

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
