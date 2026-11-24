from __future__ import annotations

import hashlib
import time
from pathlib import Path

import criptografia as cripto
from crud import Boveda, ErrorClaveIncorrecta

# La contraseña real es la ultima de la lista
CANDIDATAS = [
    "12345678", "123456789", "contrasena", "contraseña", "password",
    "password1", "password123", "qwerty123", "qwertyuiop", "abc12345",
    "iloveyou", "princesa", "corazón", "corazon1", "futbol123",
    "barcelona", "real madrid", "riverplate", "boca1234", "chile2024",
    "santiago", "valparaiso", "invierno", "verano2023", "primavera24",
    "otoño2024", "navidad24", "cumple2024", "familia123", "mascota123",
    "mipassword", "seguridad", "admin2024", "usuario123", "sistemas",
    "computacion", "universidad", "alumno2024", "llave2024", "Jiajun123!",
]
MAESTRA = CANDIDATAS[-1]

CONFIGURACIONES = [
    ("A", cripto.ParametrosKDF(time_cost=1, memory_cost=8 * 1024, parallelism=1)),
    ("C", cripto.ParametrosKDF(time_cost=3, memory_cost=64 * 1024, parallelism=4)),
]

RUTA = Path(__file__).with_name("boveda-benchmark.json")


def probar(nombre: str, parametros: cripto.ParametrosKDF) -> None:
    RUTA.unlink(missing_ok=True)
    try:
        boveda = Boveda(RUTA, parametros)
        boveda.crear(MAESTRA)
        boveda.crear_credencial("correo@ejemplo.com", "ana", "ClaveCorreo123")
        boveda.bloquear()
        huella = hashlib.sha256(RUTA.read_bytes()).hexdigest()

        inicio = time.perf_counter()
        acierto = 0
        for posicion, candidata in enumerate(CANDIDATAS, start=1):
            try:
                boveda.desbloquear(candidata)
            except ErrorClaveIncorrecta:
                continue
            acierto = posicion
            break
        total = time.perf_counter() - inicio
        boveda.bloquear()

        intacto = hashlib.sha256(RUTA.read_bytes()).hexdigest() == huella
        print(
            f"{nombre:<3}{len(CANDIDATAS):>3} intentos | acierto en {acierto} | "
            f"{total / len(CANDIDATAS) * 1000:6.1f} ms por intento | "
            f"{total:5.2f} s en total | archivo intacto: "
            f"{'si' if intacto else 'NO'}"
        )
        if acierto == 0:
            print(f"  (con la configuracion {nombre} no se acerto la contrasena)")
    finally:
        RUTA.unlink(missing_ok=True)


def main() -> int:
    print(f"Diccionario de {len(CANDIDATAS)} contrasenas debiles "
          f"(la correcta esta en la posicion {len(CANDIDATAS)}):")
    for nombre, parametros in CONFIGURACIONES:
        probar(nombre, parametros)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
