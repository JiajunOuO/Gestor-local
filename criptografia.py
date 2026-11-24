from __future__ import annotations

import secrets
import unicodedata
from dataclasses import dataclass
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


LONGITUD_SALT = 16
LONGITUD_NONCE = 12

LONGITUD_CLAVE = 32

LONGITUD_ETIQUETA = 16

ALGORITMO_KDF = "argon2id"

#limite pra ataque con parametro KDF grandes, defensa DOS
_TIME_COST_MAXIMO = 20
_MEMORIA_MAXIMA_KIB = 2 * 1024 * 1024
_PARALELISMO_MAXIMO = 16


class ErrorCriptografico(Exception):
    """Error genérico de la criptográfica."""


class ErrorIntegridad(ErrorCriptografico):
    """Los datos fueron alterados o la clave usada no es la correcta."""


@dataclass(frozen=True)
class ParametrosKDF:
    time_cost: int = 3
    memory_cost: int = 65536#64 MiB
    parallelism: int = 4
    hash_len: int = LONGITUD_CLAVE

    def __post_init__(self) -> None:
        if not 1 <= self.time_cost <= _TIME_COST_MAXIMO:
            raise ValueError("time_cost fuera de rango")
        if not 8 <= self.memory_cost <= _MEMORIA_MAXIMA_KIB:
            raise ValueError("memory_cost fuera de rango")
        if not 1 <= self.parallelism <= _PARALELISMO_MAXIMO:
            raise ValueError("parallelism fuera de rango")
        if self.memory_cost < 8 * self.parallelism:
            raise ValueError("memory_cost debe ser al menos 8 * parallelism")
        if self.hash_len != LONGITUD_CLAVE:
            raise ValueError("hash_len debe ser 32 bytes (AES-256)")

    def a_diccionario(self) -> dict[str, Any]:
        return {
            "algoritmo": ALGORITMO_KDF,
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "hash_len": self.hash_len,
        }

    @classmethod
    def desde_diccionario(cls, datos: Any) -> "ParametrosKDF":
        if not isinstance(datos, dict):
            raise ErrorCriptografico("Los parámetros KDF no son un objeto válido")
        if datos.get("algoritmo") != ALGORITMO_KDF:
            raise ErrorCriptografico(
                f"Algoritmo de derivación no soportado: {datos.get('algoritmo')!r}"
            )
        valores: dict[str, int] = {}
        for campo in ("time_cost", "memory_cost", "parallelism", "hash_len"):
            valor = datos.get(campo)
            if isinstance(valor, bool) or not isinstance(valor, int):#evitar usar true como 1
                raise ErrorCriptografico(f"Parámetro KDF inválido: {campo}")
            valores[campo] = valor
        try:
            return cls(**valores)
        except ValueError as exc:
            raise ErrorCriptografico(f"Parámetros KDF inválidos: {exc}") from exc


def generar_salt() -> bytes:
    return secrets.token_bytes(LONGITUD_SALT)


def normalizar_contrasena(contrasena: str) -> bytes:
    if not isinstance(contrasena, str):
        raise ErrorCriptografico("La contraseña debe ser texto")
    if not contrasena:
        raise ErrorCriptografico("La contraseña no puede estar vacía")
    return unicodedata.normalize("NFKC", contrasena).encode("utf-8")


def derivar_clave(contrasena: str, salt: bytes, parametros: ParametrosKDF | None = None) -> bytearray:
    if parametros is None:
        parametros = ParametrosKDF()
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != LONGITUD_SALT:
        raise ErrorCriptografico("El salt debe tener 16 bytes")

    clave = hash_secret_raw(
        secret=normalizar_contrasena(contrasena),
        salt=bytes(salt),
        time_cost=parametros.time_cost,
        memory_cost=parametros.memory_cost,
        parallelism=parametros.parallelism,
        hash_len=parametros.hash_len,
        type=Type.ID,#Argon2id
    )
    return bytearray(clave)


def cifrar(clave: bytes | bytearray, datos: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    if not isinstance(datos, (bytes, bytearray)):
        raise ErrorCriptografico("Los datos a cifrar deben ser bytes")
    nonce = secrets.token_bytes(LONGITUD_NONCE)
    try:
        texto_cifrado = AESGCM(bytes(clave)).encrypt(nonce, bytes(datos), bytes(aad))
    except (TypeError, ValueError) as exc:
        raise ErrorCriptografico(f"No se pudo cifrar: {exc}") from exc
    return nonce, texto_cifrado


def descifrar(clave: bytes | bytearray, nonce: bytes, texto_cifrado: bytes, aad: bytes = b"") -> bytes:
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != LONGITUD_NONCE:
        raise ErrorIntegridad("Nonce inválido")
    if not isinstance(texto_cifrado, (bytes, bytearray)):
        raise ErrorIntegridad("Texto cifrado inválido")
    if len(texto_cifrado) < LONGITUD_ETIQUETA:
        raise ErrorIntegridad("Texto cifrado demasiado corto")
    try:
        return AESGCM(bytes(clave)).decrypt(bytes(nonce), bytes(texto_cifrado), bytes(aad))
    except InvalidTag as exc:
        raise ErrorIntegridad("No se pudo verificar la integridad de los datos") from exc
    except (TypeError, ValueError) as exc:
        raise ErrorIntegridad(f"Datos cifrados inválidos: {exc}") from exc


def limpiar_clave(clave: bytearray | None) -> None:
    if clave:
        for i in range(len(clave)):
            clave[i] = 0


_MINUSCULAS = "abcdefghijkmnpqrstuvwxyz"
_MAYUSCULAS = "ABCDEFGHJKMNPQRSTUVWXYZ"
_LETRAS = _MINUSCULAS + _MAYUSCULAS
_DIGITOS = "23456789"
_SIMBOLOS = "!@#$%^&*()-_=+[]{};:,.?"


def generar_contrasena(longitud: int = 20, usar_simbolos: bool = True) -> str:
    if isinstance(longitud, bool) or not isinstance(longitud, int):
        raise ErrorCriptografico("La longitud debe ser un entero")
    if not 8 <= longitud <= 128:
        raise ErrorCriptografico("La longitud debe estar entre 8 y 128")

    alfabeto = _LETRAS + _DIGITOS + (_SIMBOLOS if usar_simbolos else "")
    obligatorios = [
        secrets.choice(_MINUSCULAS),
        secrets.choice(_MAYUSCULAS),
        secrets.choice(_DIGITOS),
    ]
    if usar_simbolos:
        obligatorios.append(secrets.choice(_SIMBOLOS))

    resto = [secrets.choice(alfabeto) for _ in range(longitud - len(obligatorios))]
    caracteres = obligatorios + resto
    for i in range(len(caracteres) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        caracteres[i], caracteres[j] = caracteres[j], caracteres[i]
    return "".join(caracteres)
