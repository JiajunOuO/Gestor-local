from __future__ import annotations

import ctypes
import statistics
import sys
import time

import criptografia as cripto

REPETICIONES = 5
CONTRASENA = "ContraseñaDePrueba2026!"

CONFIGURACIONES = [
    ("A", cripto.ParametrosKDF(time_cost=1, memory_cost=8 * 1024, parallelism=1)),
    ("B", cripto.ParametrosKDF(time_cost=2, memory_cost=32 * 1024, parallelism=2)),
    ("C", cripto.ParametrosKDF(time_cost=3, memory_cost=64 * 1024, parallelism=4)),
    ("D", cripto.ParametrosKDF(time_cost=4, memory_cost=128 * 1024, parallelism=4)),
]


class _ContadoresMemoria(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong),
        ("PageFaultCount", ctypes.c_ulong),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def _lector_memoria():
    if sys.platform == "win32":
        psapi = ctypes.WinDLL("psapi")
        kernel32 = ctypes.WinDLL("kernel32")
        psapi.GetProcessMemoryInfo.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_ContadoresMemoria),
            ctypes.c_uint32,
        ]
        psapi.GetProcessMemoryInfo.restype = ctypes.c_int
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p

        def pico() -> int:
            contadores = _ContadoresMemoria()
            ok = psapi.GetProcessMemoryInfo(
                kernel32.GetCurrentProcess(),
                ctypes.byref(contadores),
                ctypes.sizeof(contadores),
            )
            if not ok:
                raise OSError("GetProcessMemoryInfo falló")
            return contadores.PeakWorkingSetSize

        return pico


def medir(parametros: cripto.ParametrosKDF) -> float:
    cripto.derivar_clave(CONTRASENA, cripto.generar_salt(), parametros)#calentar
    tiempos = []
    for _ in range(REPETICIONES):
        salt = cripto.generar_salt()
        inicio = time.perf_counter()
        cripto.derivar_clave(CONTRASENA, salt, parametros)
        tiempos.append(time.perf_counter() - inicio)
    return statistics.median(tiempos)


def main(argv: list[str]) -> int:
    if argv:
        try:
            time_cost, memory_cost, parallelism = (int(x) for x in argv[:3])
            configuraciones = [("personalizada", cripto.ParametrosKDF(time_cost, memory_cost, parallelism))]
        except (ValueError, TypeError):
            print("Uso: python benchmark_argon2.py [time_cost memory_cost parallelism]")
            return 2
    else:
        configuraciones = CONFIGURACIONES

    pico = _lector_memoria()
    base = pico()

    print(
        f"{'Config':<14}{'t':>3}{'m (MiB)':>9}{'p':>3}"
        f"{'Tiempo':>12}{'Pico RSS (MiB)':>16}"
    )
    for nombre, parametros in configuraciones:
        mediana = medir(parametros)
        memoria = max(0, pico() - base) / (1024 * 1024)
        print(
            f"{nombre:<14}{parametros.time_cost:>3}"
            f"{parametros.memory_cost // 1024:>9}{parametros.parallelism:>3}"
            f"{mediana * 1000:>9.1f} ms{memoria:>10.1f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
