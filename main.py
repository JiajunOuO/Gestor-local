from __future__ import annotations

import argparse
import sys
from pathlib import Path


def ruta_predeterminada() -> Path:
    return Path.home() / ".gestor-contrasenas" / "boveda.json"


def construir_analizador() -> argparse.ArgumentParser:
    analizador = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "Gestor de contraseñas local: cifra tus credenciales con "
            "Argon2id y AES-256-GCM en un único archivo de este equipo."
        ),
    )
    analizador.add_argument(
        "--boveda",
        metavar="RUTA",
        type=Path,
        default=None,
        help=(
            "archivo donde se guardan las credenciales cifradas "
            f"(por omisión: {ruta_predeterminada()})"
        ),
    )
    return analizador


def main(argv: list[str] | None = None) -> int:
    argumentos = construir_analizador().parse_args(argv)
    ruta = (argumentos.boveda.expanduser() if argumentos.boveda is not None else ruta_predeterminada())
    ruta = ruta.resolve()

    try:
        from gui import Aplicacion
    except ModuleNotFoundError as exc:
        print(
            f"Falta la dependencia «{exc.name}».\n"
            "Instala las dependencias con:\n"
            "    python -m pip install -r requirements.txt",
            file=sys.stderr,
        )
        return 1

    try:
        aplicacion = Aplicacion(ruta)
        aplicacion.mainloop()
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"No se pudo iniciar la interfaz gráfica: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
