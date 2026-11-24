from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import tempfile
import unittest
import uuid
from collections.abc import Callable
from pathlib import Path

import criptografia as cripto
import crud
from crud import Boveda, ErrorBoveda, ErrorClaveIncorrecta

MAESTRA = "ClaveMaestra123!"
SITIO = "correo@ejemplo.com"
USUARIO = "ana"
SECRETO = "ClaveCorreo123"
NOTAS = "nota privada"
SITIO2 = "banco.ejemplo"
USUARIO2 = "ana.lopez"
SECRETO2 = "ClaveBanco456"
PARAMETROS_RAPIDOS = cripto.ParametrosKDF(time_cost=1, memory_cost=8192, parallelism=1)


def _directorio_base_pruebas() -> Path:
    base = os.environ.get("GESTOR_PRUEBAS_DIR")
    if base:
        ruta = Path(base).expanduser()
        ruta.mkdir(parents=True, exist_ok=True)
        return ruta
    return Path(tempfile.gettempdir())


class BaseRobustez(unittest.TestCase):
    def setUp(self) -> None:
        self.ruta = _directorio_base_pruebas() / f"robustez-{uuid.uuid4().hex}.json"
        boveda = Boveda(self.ruta, PARAMETROS_RAPIDOS)
        boveda.crear(MAESTRA)
        boveda.crear_credencial(SITIO, USUARIO, SECRETO, NOTAS)
        boveda.crear_credencial(SITIO2, USUARIO2, SECRETO2)
        boveda.bloquear()
        self.original = self.ruta.read_bytes()
        self.datos_originales = json.loads(self.original)
        self.secretos_b64 = self._valores_base64(self.datos_originales)

    def tearDown(self) -> None:
        try:
            os.chmod(self.ruta, stat.S_IWRITE | stat.S_IREAD)
        except OSError:
            pass
        self.ruta.unlink(missing_ok=True)

    @staticmethod
    def _valores_base64(datos: dict) -> list[str]:
        valores = [datos["kdf"]["salt"], datos["mac"]]
        for entrada in datos["credenciales"]:
            valores.append(entrada["nonce"])
            valores.append(entrada["ciphertext"])
        return [valor for valor in valores if isinstance(valor, str)]

    def leer_json(self) -> dict:
        return json.loads(self.ruta.read_text(encoding="utf-8"))

    def escribir_json(self, datos: object) -> None:
        self.ruta.write_text(json.dumps(datos), encoding="utf-8")

    def escribir_crudo(self, texto: str) -> None:
        self.ruta.write_text(texto, encoding="utf-8")

    def restaurar(self) -> None:
        self.ruta.write_bytes(self.original)

    def instantanea(self) -> tuple[str, int]:
        return (
            hashlib.sha256(self.ruta.read_bytes()).hexdigest(),
            self.ruta.stat().st_mtime_ns,
        )

    def _assert_sin_filtraciones(self, mensaje: str) -> None:
        for prohibido in (MAESTRA, SECRETO, SECRETO2, USUARIO, USUARIO2, SITIO, SITIO2, NOTAS):
            self.assertNotIn(prohibido, mensaje)
        for valor in self.secretos_b64:
            self.assertNotIn(valor, mensaje)

    def comprobar_rechazo(self, contrasena: str = MAESTRA, tipo: type[Exception] = ErrorBoveda) -> Exception:
        antes = self.instantanea()
        boveda = Boveda(self.ruta)
        with self.assertRaises((ErrorClaveIncorrecta, ErrorBoveda)) as capturado:
            boveda.desbloquear(contrasena)
        self.assertIsInstance(capturado.exception, tipo)
        self._assert_sin_filtraciones(str(capturado.exception))
        self.assertFalse(boveda.desbloqueada)
        with self.assertRaises(ErrorBoveda):
            boveda.listar()
        self.assertEqual(self.instantanea(), antes, "el intento fallido modificó el archivo")
        return capturado.exception

    def comprobar_recuperacion(self) -> None:
        boveda = Boveda(self.ruta)
        boveda.desbloquear(MAESTRA)
        credenciales = {credencial.sitio: credencial for credencial in boveda.listar()}
        self.assertEqual(len(credenciales), 2)
        self.assertEqual(credenciales[SITIO].contrasena, SECRETO)
        self.assertEqual(credenciales[SITIO].usuario, USUARIO)
        self.assertEqual(credenciales[SITIO].notas, NOTAS)
        self.assertEqual(credenciales[SITIO2].contrasena, SECRETO2)
        boveda.bloquear()


class PruebasAlteracionBinaria(BaseRobustez):
    def _voltear_bit(self, campo: str) -> None:
        datos = self.leer_json()
        if campo == "salt":
            crudo = bytearray(base64.b64decode(datos["kdf"]["salt"]))
            crudo[0] ^= 0x01
            datos["kdf"]["salt"] = base64.b64encode(bytes(crudo)).decode("ascii")
        elif campo == "mac":
            crudo = bytearray(base64.b64decode(datos["mac"]))
            crudo[0] ^= 0x01
            datos["mac"] = base64.b64encode(bytes(crudo)).decode("ascii")
        else:
            entrada = datos["credenciales"][0]
            crudo = bytearray(base64.b64decode(entrada[campo]))
            crudo[0] ^= 0x01
            entrada[campo] = base64.b64encode(bytes(crudo)).decode("ascii")
        self.escribir_json(datos)

    def _comprobar_campo(self, campo: str) -> None:
        self._voltear_bit(campo)
        self.comprobar_rechazo(tipo=ErrorClaveIncorrecta)
        self.restaurar()
        self.comprobar_recuperacion()

    def test_bit_en_el_ciphertext(self) -> None:
        self._comprobar_campo("ciphertext")

    def test_bit_en_el_nonce(self) -> None:
        self._comprobar_campo("nonce")

    def test_bit_en_el_salt(self) -> None:
        self._comprobar_campo("salt")

    def test_bit_en_el_mac(self) -> None:
        self._comprobar_campo("mac")


class PruebasTruncado(BaseRobustez):
    def test_cortes_en_varias_posiciones(self) -> None:
        tamano = len(self.original)
        cortes = (0, 1, 2, tamano // 2, tamano - 16, tamano - 1)
        for corte in cortes:
            with self.subTest(corte=corte):
                self.ruta.write_bytes(self.original[:corte])
                self.comprobar_rechazo()
                self.restaurar()
        self.comprobar_recuperacion()


class PruebasContrasena(BaseRobustez):
    def test_contrasena_vacia(self) -> None:
        self.comprobar_rechazo("", tipo=ErrorClaveIncorrecta)

    def test_contrasena_que_difiere_en_un_caracter(self) -> None:
        self.comprobar_rechazo("ClaveMaestra124!", tipo=ErrorClaveIncorrecta)

    def test_mayusculas_distintas(self) -> None:
        self.comprobar_rechazo("clavemaestra123!", tipo=ErrorClaveIncorrecta)

    def test_caracteres_parecidos(self) -> None:
        self.comprobar_rechazo("C1aveMaestra123!", tipo=ErrorClaveIncorrecta)

    def test_contrasena_muy_larga(self) -> None:
        self.comprobar_rechazo("x" * 2000, tipo=ErrorClaveIncorrecta)

    def test_tipo_incorrecto(self) -> None:
        with self.assertRaises(ErrorClaveIncorrecta):
            Boveda(self.ruta).desbloquear(12345)

    def test_mensaje_identico_para_clave_incorrecta_y_archivo_alterado(self) -> None:
        incorrecta = self.comprobar_rechazo("ClaveIncorrecta999!", tipo=ErrorClaveIncorrecta)

        datos = self.leer_json()
        datos["mac"] = base64.b64encode(b"\x00" * 32).decode("ascii")
        self.escribir_json(datos)
        alterada = self.comprobar_rechazo(tipo=ErrorClaveIncorrecta)

        self.assertEqual(str(incorrecta), str(alterada))
        self.restaurar()
        self.comprobar_recuperacion()


class PruebasEstructura(BaseRobustez):
    def _mutar_y_comprobar(self, mutador: Callable[[dict], None], tipo: type[Exception] = ErrorBoveda) -> None:
        datos = self.leer_json()
        mutador(datos)
        self.escribir_json(datos)
        self.comprobar_rechazo(tipo=tipo)
        self.restaurar()
        self.comprobar_recuperacion()

    def test_json_que_no_es_objeto(self) -> None:
        for texto in ("[]", "null", '"texto"', "123", "true"):
            with self.subTest(texto=texto):
                self.escribir_crudo(texto)
                self.comprobar_rechazo()
        self.restaurar()
        self.comprobar_recuperacion()

    def test_formato_desconocido(self) -> None:
        self._mutar_y_comprobar(lambda datos: datos.__setitem__("formato", "otra-cosa"))

    def test_version_futura(self) -> None:
        self._mutar_y_comprobar(lambda datos: datos.__setitem__("version", 99))

    def test_version_no_entera(self) -> None:
        self._mutar_y_comprobar(lambda datos: datos.__setitem__("version", "1"))

    def test_faltan_los_parametros_kdf(self) -> None:
        self._mutar_y_comprobar(lambda datos: datos.pop("kdf"))

    def test_kdf_no_es_objeto(self) -> None:
        self._mutar_y_comprobar(lambda datos: datos.__setitem__("kdf", "argon2id"))

    def test_parametros_kdf_fuera_de_rango(self) -> None:
        self._mutar_y_comprobar(
            lambda datos: datos["kdf"].__setitem__("memory_cost", 1)
        )

    def test_credenciales_no_es_lista(self) -> None:
        self._mutar_y_comprobar(
            lambda datos: datos.__setitem__("credenciales", {}),
            tipo=ErrorClaveIncorrecta,
        )

    def test_credencial_sin_identificador(self) -> None:
        self._mutar_y_comprobar(
            lambda datos: datos["credenciales"][0].pop("id"),
            tipo=ErrorClaveIncorrecta,
        )

    def test_credenciales_duplicadas(self) -> None:
        def duplicar(datos: dict) -> None:
            datos["credenciales"].append(dict(datos["credenciales"][0]))

        self._mutar_y_comprobar(duplicar, tipo=ErrorClaveIncorrecta)

    def test_falta_el_mac(self) -> None:
        self._mutar_y_comprobar(lambda datos: datos.pop("mac"))

    def test_mac_que_no_es_base64(self) -> None:
        self._mutar_y_comprobar(lambda datos: datos.__setitem__("mac", "***"))


class PruebasTamano(BaseRobustez):
    def test_archivo_demasiado_grande(self) -> None:
        self.ruta.write_bytes(b"x" * (crud.MAX_TAMANO_ARCHIVO + 1))
        self.comprobar_rechazo()
        self.restaurar()
        self.comprobar_recuperacion()

if __name__ == "__main__":
    unittest.main()
