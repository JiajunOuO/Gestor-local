from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import tempfile
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import criptografia as cripto

FORMATO = "gestor-contrasenas-local"
VERSION = 1

_INFO_CLAVE_MAC = b"gestor-contrasenas-local/mac/v1"
_AAD_CREDENCIAL = b"gestor-contrasenas-local/credencial/v1/"


MAX_TAMANO_ARCHIVO = 32 * 1024 * 1024
LONGITUD_MINIMA_MAESTRA = 8
LONGITUD_MAXIMA_TEXTO = 1024
LONGITUD_MAXIMA_NOTAS = 8192


class ErrorBoveda(Exception):
    """Error controlado de la bóveda (se muestra al usuario sin traza)."""


class ErrorClaveIncorrecta(ErrorBoveda):
    """La contraseña maestra no es correcta o el archivo fue alterado."""


class ErrorCredencialNoExiste(ErrorBoveda):
    """No hay ninguna credencial con ese identificador."""


class ErrorDatosInvalidos(ErrorBoveda):
    """Los datos entregados por el usuario no son válidos."""


def _ahora() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _b64(datos: bytes) -> str:
    return base64.b64encode(datos).decode("ascii")


def _desde_b64(texto: Any, campo: str) -> bytes: #Validar que no es cambiado
    if not isinstance(texto, str):
        raise ErrorBoveda(f"El campo {campo} no es base64")
    try:
        return base64.b64decode(texto.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise ErrorBoveda(f"El campo {campo} no es base64 válido") from exc


def _validar_texto(valor: Any, campo: str, maximo: int = LONGITUD_MAXIMA_TEXTO) -> str:
    if not isinstance(valor, str):
        raise ErrorDatosInvalidos(f"El campo {campo} debe ser texto")
    valor = valor.strip()
    if not valor:
        raise ErrorDatosInvalidos(f"El campo {campo} no puede estar vacío")
    if len(valor) > maximo:
        raise ErrorDatosInvalidos(f"El campo {campo} es demasiado largo")
    return valor


def _validar_secreto(valor: Any, campo: str, maximo: int = LONGITUD_MAXIMA_TEXTO) -> str:
    if not isinstance(valor, str):
        raise ErrorDatosInvalidos(f"El campo {campo} debe ser texto")
    if not valor:
        raise ErrorDatosInvalidos(f"El campo {campo} no puede estar vacío")
    if len(valor) > maximo:
        raise ErrorDatosInvalidos(f"El campo {campo} es demasiado largo")
    return valor


@dataclass(frozen=True)
class Credencial:
    id: str
    sitio: str
    usuario: str
    contrasena: str
    notas: str = ""
    creado: str = ""
    modificado: str = ""

    def a_diccionario(self) -> dict[str, str]:
        return {
            "sitio": self.sitio,
            "usuario": self.usuario,
            "contrasena": self.contrasena,
            "notas": self.notas,
            "creado": self.creado,
            "modificado": self.modificado,
        }

    @classmethod
    def desde_diccionario(cls, identificador: str, datos: Any) -> "Credencial":
        if not isinstance(datos, dict):
            raise ErrorBoveda("Una credencial almacenada no es válida")
        sitio = _validar_texto(datos.get("sitio"), "sitio")
        usuario = _validar_texto(datos.get("usuario"), "usuario")
        contrasena = _validar_secreto(datos.get("contrasena"), "contraseña")
        notas = datos.get("notas", "")
        if not isinstance(notas, str) or len(notas) > LONGITUD_MAXIMA_NOTAS:
            raise ErrorBoveda("Las notas de una credencial no son válidas")
        creado = datos.get("creado", "")
        modificado = datos.get("modificado", "")
        for valor in (creado, modificado):
            if not isinstance(valor, str) or len(valor) > 64:
                raise ErrorBoveda("La fecha de una credencial no es válida")
        return cls(
            id=identificador,
            sitio=sitio,
            usuario=usuario,
            contrasena=contrasena,
            notas=notas,
            creado=creado,
            modificado=modificado,
        )


def _escribir_atomico(ruta: Path, contenido: bytes) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporal = tempfile.mkstemp(prefix=".boveda-", suffix=".tmp", dir=str(ruta.parent))
    try:
        with os.fdopen(descriptor, "wb") as archivo:
            archivo.write(contenido)
            archivo.flush()
            os.fsync(archivo.fileno())
        if os.name == "posix":#pal linux, mac
            os.chmod(temporal, 0o600)#rw
        os.replace(temporal, ruta)
    except BaseException:
        try:
            os.unlink(temporal)#borrar
        except OSError:
            pass
        raise


class Boveda:
    def __init__(self, ruta: str | Path, parametros_kdf: cripto.ParametrosKDF | None = None) -> None:
        self.ruta = Path(ruta)
        self.parametros_kdf = parametros_kdf or cripto.ParametrosKDF()
        self._clave: bytearray | None = None
        self._salt: bytes | None = None
        self._parametros_guardados: cripto.ParametrosKDF | None = None
        self._credenciales: dict[str, Credencial] = {}

    @property
    def existe(self) -> bool:
        return self.ruta.is_file()

    @property
    def desbloqueada(self) -> bool:
        return self._clave is not None

    def _requiere_desbloqueada(self) -> None:
        if not self.desbloqueada:
            raise ErrorBoveda("La bóveda está bloqueada")

    @staticmethod
    def _validar_contrasena_maestra(contrasena: Any) -> str:
        if not isinstance(contrasena, str):
            raise ErrorDatosInvalidos("La contraseña maestra debe ser texto")
        if len(contrasena) < LONGITUD_MINIMA_MAESTRA:
            raise ErrorDatosInvalidos(
                f"La contraseña maestra debe tener al menos {LONGITUD_MINIMA_MAESTRA} caracteres"
            )
        if len(contrasena) > 1024:
            raise ErrorDatosInvalidos("La contraseña maestra es demasiado larga")
        return contrasena

    def crear(self, contrasena_maestra: str) -> None:
        if self.existe:
            raise ErrorBoveda(
                f"Ya existe una bóveda en {self.ruta}"
            )
        contrasena = self._validar_contrasena_maestra(contrasena_maestra)
        salt = cripto.generar_salt()
        clave = cripto.derivar_clave(contrasena, salt, self.parametros_kdf)

        self._clave = clave
        self._salt = salt
        self._parametros_guardados = self.parametros_kdf
        self._credenciales = {}
        try:
            self._guardar()
        except BaseException:
            self.bloquear()
            raise

    def desbloquear(self, contrasena_maestra: str) -> None:#
        if self.desbloqueada:
            self.bloquear()
        if not self.existe:
            raise ErrorBoveda(f"No existe ninguna bóveda en {self.ruta}")
        if not isinstance(contrasena_maestra, str) or not contrasena_maestra:
            raise ErrorClaveIncorrecta("Contraseña maestra incorrecta")

        datos = self._leer_archivo()
        version = datos.get("version")
        if isinstance(version, bool) or not isinstance(version, int):
            raise ErrorBoveda("La versión de la bóveda no es válida")
        if version > VERSION:
            raise ErrorBoveda(
                "La bóveda fue creada con una versión más reciente del programa"
            )
        if version < 1:
            raise ErrorBoveda("La versión de la bóveda no es compatible")

        kdf_crudo = datos.get("kdf")
        if not isinstance(kdf_crudo, dict):
            raise ErrorBoveda("Faltan los parámetros de derivación de la bóveda")
        try:
            parametros = cripto.ParametrosKDF.desde_diccionario(kdf_crudo)
        except cripto.ErrorCriptografico as exc:
            raise ErrorBoveda(str(exc)) from exc
        salt = _desde_b64(kdf_crudo.get("salt"), "salt")
        if len(salt) != cripto.LONGITUD_SALT:
            raise ErrorBoveda("El salt de la bóveda no es válido")

        clave = cripto.derivar_clave(contrasena_maestra, salt, parametros)
        try:
            if not self._mac_valido(datos, clave):
                raise ErrorClaveIncorrecta(
                    "Contraseña maestra incorrecta o bóveda alterada"
                )
            credenciales = self._descifrar_credenciales(datos, clave)
        except BaseException:
            cripto.limpiar_clave(clave)
            raise

        self._clave = clave
        self._salt = salt
        self._parametros_guardados = parametros
        self._credenciales = credenciales

    def bloquear(self) -> None:
        cripto.limpiar_clave(self._clave)
        self._clave = None
        self._salt = None
        self._parametros_guardados = None
        self._credenciales = {}


    def _leer_archivo(self) -> dict[str, Any]:
        try:
            tamano = self.ruta.stat().st_size
        except OSError as exc:
            raise ErrorBoveda(f"No se pudo leer la bóveda: {exc}") from exc
        if tamano > MAX_TAMANO_ARCHIVO:
            raise ErrorBoveda("El archivo de la bóveda es demasiado grande")
        try:
            texto = self.ruta.read_text(encoding="utf-8-sig")
            datos = json.loads(texto)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ErrorBoveda("El archivo de la bóveda está dañado o no es válido") from exc
        if not isinstance(datos, dict):
            raise ErrorBoveda("El archivo de la bóveda no tiene el formato esperado")
        if datos.get("formato") != FORMATO:
            raise ErrorBoveda("El archivo no es una bóveda de este programa")
        return datos

    @staticmethod
    def _cuerpo_firmado(datos: dict[str, Any]) -> bytes:
        try:
            cuerpo = {campo: datos[campo] for campo in ("formato", "version", "kdf", "credenciales")}
        except KeyError as exc:
            raise ErrorBoveda("La bóveda está incompleta") from exc
        return json.dumps(cuerpo, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @staticmethod
    def _clave_mac(clave: bytes | bytearray) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=_INFO_CLAVE_MAC,
        ).derive(bytes(clave))

    def _calcular_mac(self, datos: dict[str, Any], clave: bytes | bytearray) -> bytes:
        return hmac.new(
            self._clave_mac(clave), self._cuerpo_firmado(datos), hashlib.sha256
        ).digest()

    def _mac_valido(self, datos: dict[str, Any], clave: bytes | bytearray) -> bool:
        mac_guardado = datos.get("mac")
        if not isinstance(mac_guardado, str):
            raise ErrorBoveda("La bóveda no tiene código de integridad")
        mac_esperado = self._calcular_mac(datos, clave)
        return hmac.compare_digest(_desde_b64(mac_guardado, "mac"), mac_esperado)

    def _descifrar_credenciales(self, datos: dict[str, Any], clave: bytes | bytearray) -> dict[str, Credencial]:
        entradas = datos.get("credenciales")
        if not isinstance(entradas, list):
            raise ErrorBoveda("La lista de credenciales no es válida")
        credenciales: dict[str, Credencial] = {}
        for entrada in entradas:
            if not isinstance(entrada, dict):
                raise ErrorBoveda("Una entrada de la bóveda no es válida")
            identificador = entrada.get("id")
            if not isinstance(identificador, str):
                raise ErrorBoveda("Una credencial no tiene identificador")
            try:
                uuid.UUID(identificador)
            except ValueError as exc:
                raise ErrorBoveda("El identificador de una credencial no es válido") from exc
            if identificador in credenciales:
                raise ErrorBoveda("Hay credenciales duplicadas en la bóveda")
            nonce = _desde_b64(entrada.get("nonce"), "nonce")
            texto_cifrado = _desde_b64(entrada.get("ciphertext"), "texto cifrado")
            try:
                plano = cripto.descifrar(
                    clave,
                    nonce,
                    texto_cifrado,
                    _AAD_CREDENCIAL + identificador.encode("utf-8"),
                )
            except cripto.ErrorIntegridad as exc:
                raise ErrorBoveda(
                    "La bóveda está dañada: una credencial no pudo verificarse"
                ) from exc
            try:
                contenido = json.loads(plano.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ErrorBoveda("Una credencial descifrada no es válida") from exc
            credenciales[identificador] = Credencial.desde_diccionario(identificador, contenido)
        return credenciales

    def _guardar(self) -> None:
        self._requiere_desbloqueada()
        assert self._clave is not None
        assert self._salt is not None
        assert self._parametros_guardados is not None

        entradas: list[dict[str, str]] = []
        for identificador, credencial in self._credenciales.items():
            plano = json.dumps(
                credencial.a_diccionario(),
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            nonce, texto_cifrado = cripto.cifrar(
                self._clave,
                plano,
                _AAD_CREDENCIAL + identificador.encode("utf-8"),
            )
            entradas.append(
                {
                    "id": identificador,
                    "nonce": _b64(nonce),
                    "ciphertext": _b64(texto_cifrado),
                }
            )

        kdf = self._parametros_guardados.a_diccionario()
        kdf["salt"] = _b64(self._salt)
        datos: dict[str, Any] = {
            "formato": FORMATO,
            "version": VERSION,
            "kdf": kdf,
            "credenciales": entradas,
        }
        datos["mac"] = _b64(self._calcular_mac(datos, self._clave))
        contenido = json.dumps(datos, ensure_ascii=False, indent=2).encode("utf-8")
        _escribir_atomico(self.ruta, contenido)

    #CRUD
    def listar(self, filtro: str = "") -> list[Credencial]:
        self._requiere_desbloqueada()
        if not isinstance(filtro, str):
            raise ErrorDatosInvalidos("El filtro debe ser texto")
        consulta = filtro.strip().casefold()
        resultado = []
        for credencial in self._credenciales.values():
            if consulta and not (consulta in credencial.sitio.casefold() or consulta in credencial.usuario.casefold()):
                continue
            resultado.append(replace(credencial))
        resultado.sort(key=lambda c: (c.sitio.casefold(), c.usuario.casefold()))
        return resultado

    def obtener(self, identificador: str) -> Credencial:
        self._requiere_desbloqueada()
        try:
            return replace(self._credenciales[identificador])
        except KeyError as exc:
            raise ErrorCredencialNoExiste("La credencial ya no existe") from exc

    def crear_credencial(self, sitio: str, usuario: str, contrasena: str, notas: str = "") -> Credencial:
        self._requiere_desbloqueada()
        sitio = _validar_texto(sitio, "sitio")
        usuario = _validar_texto(usuario, "usuario")
        contrasena = _validar_secreto(contrasena, "contraseña")
        if not isinstance(notas, str) or len(notas) > LONGITUD_MAXIMA_NOTAS:
            raise ErrorDatosInvalidos("Las notas no son válidas")
        ahora = _ahora()
        credencial = Credencial(
            id=uuid.uuid4().hex,
            sitio=sitio,
            usuario=usuario,
            contrasena=contrasena,
            notas=notas.strip(),
            creado=ahora,
            modificado=ahora,
        )
        self._credenciales[credencial.id] = credencial
        try:
            self._guardar()
        except BaseException:
            del self._credenciales[credencial.id]
            raise
        return replace(credencial)

    def actualizar_credencial(self, identificador: str, sitio: str | None = None, usuario: str | None = None, contrasena: str | None = None, notas: str | None = None) -> Credencial:
        self._requiere_desbloqueada()
        anterior = self._credenciales.get(identificador)
        if anterior is None:
            raise ErrorCredencialNoExiste("La credencial ya no existe")

        cambios: dict[str, str] = {}
        if sitio is not None:
            cambios["sitio"] = _validar_texto(sitio, "sitio")
        if usuario is not None:
            cambios["usuario"] = _validar_texto(usuario, "usuario")
        if contrasena is not None:
            cambios["contrasena"] = _validar_secreto(contrasena, "contraseña")
        if notas is not None:
            if not isinstance(notas, str) or len(notas) > LONGITUD_MAXIMA_NOTAS:
                raise ErrorDatosInvalidos("Las notas no son válidas")
            cambios["notas"] = notas.strip()

        actualizada = replace(anterior, modificado=_ahora(), **cambios)
        self._credenciales[identificador] = actualizada
        try:
            self._guardar()
        except BaseException:
            self._credenciales[identificador] = anterior
            raise
        return replace(actualizada)

    def eliminar_credencial(self, identificador: str) -> None:
        self._requiere_desbloqueada()
        anterior = self._credenciales.pop(identificador, None)
        if anterior is None:
            raise ErrorCredencialNoExiste("La credencial ya no existe")
        try:
            self._guardar()
        except BaseException:
            self._credenciales[identificador] = anterior
            raise
