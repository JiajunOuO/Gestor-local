from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import criptografia as cripto
from crud import (
    Boveda,
    ErrorBoveda,
    ErrorClaveIncorrecta,
    ErrorCredencialNoExiste,
    ErrorDatosInvalidos,
)

MAESTRA = "ClaveMaestra123!"
PARAMETROS_RAPIDOS = cripto.ParametrosKDF(time_cost=1, memory_cost=8192, parallelism=1)


def _directorio_base_pruebas() -> Path:
    base = os.environ.get("GESTOR_PRUEBAS_DIR")
    if base:
        ruta = Path(base).expanduser()
        ruta.mkdir(parents=True, exist_ok=True)
        return ruta
    return Path(tempfile.gettempdir())



class BasePruebasBoveda(unittest.TestCase):
    def setUp(self) -> None:
        self.ruta = _directorio_base_pruebas() / f"boveda-{uuid.uuid4().hex}.json"
        self.boveda = Boveda(self.ruta, PARAMETROS_RAPIDOS)
        self.boveda.crear(MAESTRA)

    def tearDown(self) -> None:
        self.boveda.bloquear()
        try:
            self.ruta.unlink()
        except FileNotFoundError:
            pass

    def leer_json(self) -> dict:
        return json.loads(self.ruta.read_text(encoding="utf-8"))

    def escribir_json(self, datos: dict) -> None:
        self.ruta.write_text(json.dumps(datos), encoding="utf-8")


class PruebasCreacion(BasePruebasBoveda):
    def test_crear_deja_la_boveda_desbloqueada(self) -> None:
        self.assertTrue(self.boveda.existe)
        self.assertTrue(self.boveda.desbloqueada)
        self.assertTrue(self.ruta.is_file())

    def test_estructura_del_archivo(self) -> None:
        datos = self.leer_json()
        self.assertEqual(datos["formato"], "gestor-contrasenas-local")
        self.assertEqual(datos["version"], 1)
        self.assertEqual(datos["kdf"]["algoritmo"], "argon2id")
        self.assertEqual(datos["kdf"]["memory_cost"], 8192)
        self.assertIn("mac", datos)
        self.assertEqual(datos["credenciales"], [])

    def test_la_contrasena_maestra_no_se_guarda(self) -> None:
        self.boveda.crear_credencial("GitHub", "jiajun", "secreto-123")
        contenido = self.ruta.read_bytes()
        self.assertNotIn(MAESTRA.encode("utf-8"), contenido)

    def test_crear_dos_veces_falla(self) -> None:
        with self.assertRaises(ErrorBoveda):
            self.boveda.crear("OtraClave456!")

    def test_contrasena_maestra_corta(self) -> None:
        ruta = _directorio_base_pruebas() / "otra.json"
        boveda = Boveda(ruta, PARAMETROS_RAPIDOS)
        with self.assertRaises(ErrorDatosInvalidos):
            boveda.crear("corta")
        self.assertFalse(ruta.exists())

    def test_desbloqueo_correcto(self) -> None:
        self.boveda.bloquear()
        self.boveda.desbloquear(MAESTRA)
        self.assertTrue(self.boveda.desbloqueada)

    def test_desbloqueo_incorrecto(self) -> None:
        self.boveda.bloquear()
        with self.assertRaises(ErrorClaveIncorrecta):
            self.boveda.desbloquear("incorrecta")
        self.assertFalse(self.boveda.desbloqueada)

    def test_boveda_vacia_tambien_verifica_la_clave(self) -> None:
        self.boveda.bloquear()
        with self.assertRaises(ErrorClaveIncorrecta):
            self.boveda.desbloquear("OtraClave456!")

    def test_bloquear_borra_el_estado(self) -> None:
        self.boveda.bloquear()
        self.assertFalse(self.boveda.desbloqueada)
        with self.assertRaises(ErrorBoveda):
            self.boveda.listar()

    def test_desbloquear_sin_archivo(self) -> None:
        ruta = _directorio_base_pruebas() / "no-existe.json"
        with self.assertRaises(ErrorBoveda):
            Boveda(ruta).desbloquear(MAESTRA)


class PruebasCRUD(BasePruebasBoveda):
    def test_crear_y_listar(self) -> None:
        creada = self.boveda.crear_credencial("GitHub", "jiajun", "s3cr3t", "2FA")
        self.assertTrue(creada.id)
        listado = self.boveda.listar()
        self.assertEqual(len(listado), 1)
        self.assertEqual(listado[0].sitio, "GitHub")
        self.assertEqual(listado[0].usuario, "jiajun")
        self.assertEqual(listado[0].contrasena, "s3cr3t")
        self.assertEqual(listado[0].notas, "2FA")

    def test_obtener_por_id(self) -> None:
        creada = self.boveda.crear_credencial("Correo", "yo", "clave")
        recuperada = self.boveda.obtener(creada.id)
        self.assertEqual(recuperada, creada)
        self.assertIsNot(recuperada, creada)

    def test_actualizar_solo_un_campo(self) -> None:
        creada = self.boveda.crear_credencial("Sitio", "usuario", "clave")
        actualizada = self.boveda.actualizar_credencial(
            creada.id, contrasena="nueva-clave"
        )
        self.assertEqual(actualizada.contrasena, "nueva-clave")
        self.assertEqual(actualizada.usuario, "usuario")
        self.assertEqual(actualizada.sitio, "Sitio")

    def test_eliminar(self) -> None:
        creada = self.boveda.crear_credencial("Sitio", "usuario", "clave")
        self.boveda.eliminar_credencial(creada.id)
        self.assertEqual(self.boveda.listar(), [])
        with self.assertRaises(ErrorCredencialNoExiste):
            self.boveda.obtener(creada.id)

    def test_id_inexistente(self) -> None:
        with self.assertRaises(ErrorCredencialNoExiste):
            self.boveda.obtener("no-existe")
        with self.assertRaises(ErrorCredencialNoExiste):
            self.boveda.actualizar_credencial("no-existe", notas="x")
        with self.assertRaises(ErrorCredencialNoExiste):
            self.boveda.eliminar_credencial("no-existe")

    def test_orden_por_sitio(self) -> None:
        for sitio in ("zeta", "Alfa", "beta"):
            self.boveda.crear_credencial(sitio, "u", "c")
        self.assertEqual([c.sitio for c in self.boveda.listar()], ["Alfa", "beta", "zeta"])

    def test_filtro_sin_distinguir_mayusculas(self) -> None:
        self.boveda.crear_credencial("GitHub", "jiajun", "c1")
        self.boveda.crear_credencial("Correo", "otro", "c2")
        self.assertEqual(len(self.boveda.listar("GIT")), 1)
        self.assertEqual(len(self.boveda.listar("jiajun")), 1)
        self.assertEqual(self.boveda.listar("nada"), [])

    def test_espacios_en_la_contrasena_se_conservan(self) -> None:
        creada = self.boveda.crear_credencial("Sitio", "usuario", "  con espacios  ")
        self.assertEqual(creada.contrasena, "  con espacios  ")
        self.assertEqual(self.boveda.obtener(creada.id).contrasena, "  con espacios  ")

    def test_notas_multilinea(self) -> None:
        notas = "línea 1\nlínea 2 con ñ y emoji 🔐"
        creada = self.boveda.crear_credencial("Sitio", "usuario", "clave", notas)
        self.assertEqual(self.boveda.obtener(creada.id).notas, notas)

    def test_sitio_o_usuario_vacio(self) -> None:
        for kwargs in (
            {"sitio": "  ", "usuario": "u", "contrasena": "c"},
            {"sitio": "s", "usuario": " ", "contrasena": "c"},
            {"sitio": "s", "usuario": "u", "contrasena": ""},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ErrorDatosInvalidos):
                    self.boveda.crear_credencial(**kwargs)

    def test_tipos_invalidos(self) -> None:
        with self.assertRaises(ErrorDatosInvalidos):
            self.boveda.crear_credencial(123, "u", "c")
        with self.assertRaises(ErrorDatosInvalidos):
            self.boveda.listar(123)

    def test_fallo_de_escritura_revierte_la_memoria(self) -> None:
        with mock.patch("crud._escribir_atomico", side_effect=OSError("disco lleno")):
            with self.assertRaises(OSError):
                self.boveda.crear_credencial("Sitio", "usuario", "clave")
        self.assertEqual(self.boveda.listar(), [])


class PruebasPersistencia(BasePruebasBoveda):
    def test_los_datos_sobreviven_al_cierre(self) -> None:
        creada = self.boveda.crear_credencial("GitHub", "jiajun", "secreto-123", "nota")
        self.boveda.bloquear()

        otra = Boveda(self.ruta)
        otra.desbloquear(MAESTRA)
        recuperada = otra.obtener(creada.id)
        self.assertEqual(recuperada.sitio, "GitHub")
        self.assertEqual(recuperada.contrasena, "secreto-123")
        self.assertEqual(recuperada.notas, "nota")

    def test_los_datos_no_estan_en_claro(self) -> None:
        self.boveda.crear_credencial("GitHub", "jiajun", "secreto-123", "nota privada")
        contenido = self.ruta.read_bytes()
        for texto in (b"GitHub", b"jiajun", b"secreto-123", b"nota privada"):
            self.assertNotIn(texto, contenido)


class PruebasIntegridad(BasePruebasBoveda):
    def test_ciphertext_alterado(self) -> None:
        self.boveda.crear_credencial("GitHub", "jiajun", "secreto-123")
        self.boveda.bloquear()
        datos = self.leer_json()
        cifrado = bytearray(base64.b64decode(datos["credenciales"][0]["ciphertext"]))
        cifrado[0] ^= 0x01
        datos["credenciales"][0]["ciphertext"] = base64.b64encode(cifrado).decode()
        self.escribir_json(datos)
        with self.assertRaises(ErrorBoveda):
            Boveda(self.ruta).desbloquear(MAESTRA)

    def test_credencial_eliminada_del_archivo(self) -> None:
        self.boveda.crear_credencial("GitHub", "jiajun", "c1")
        self.boveda.crear_credencial("Correo", "yo", "c2")
        self.boveda.bloquear()
        datos = self.leer_json()
        del datos["credenciales"][0]
        self.escribir_json(datos)
        with self.assertRaises(ErrorClaveIncorrecta):
            Boveda(self.ruta).desbloquear(MAESTRA)

    def test_credenciales_reordenadas(self) -> None:
        self.boveda.crear_credencial("GitHub", "jiajun", "c1")
        self.boveda.crear_credencial("Correo", "yo", "c2")
        self.boveda.bloquear()
        datos = self.leer_json()
        datos["credenciales"].reverse()
        self.escribir_json(datos)
        with self.assertRaises(ErrorClaveIncorrecta):
            Boveda(self.ruta).desbloquear(MAESTRA)

    def test_mac_alterado(self) -> None:
        self.boveda.bloquear()
        datos = self.leer_json()
        mac = bytearray(base64.b64decode(datos["mac"]))
        mac[0] ^= 0x01
        datos["mac"] = base64.b64encode(mac).decode()
        self.escribir_json(datos)
        with self.assertRaises(ErrorClaveIncorrecta):
            Boveda(self.ruta).desbloquear(MAESTRA)

    def test_parametros_kdf_manipulados(self) -> None:
        self.boveda.bloquear()
        datos = self.leer_json()
        datos["kdf"]["memory_cost"] = 10 ** 9  #agotar memoria
        self.escribir_json(datos)
        with self.assertRaises(ErrorBoveda):
            Boveda(self.ruta).desbloquear(MAESTRA)

    def test_version_futura(self) -> None:
        self.boveda.bloquear()
        datos = self.leer_json()
        datos["version"] = 99
        self.escribir_json(datos)
        with self.assertRaises(ErrorBoveda):
            Boveda(self.ruta).desbloquear(MAESTRA)

    def test_archivo_ajeno(self) -> None:
        self.boveda.bloquear()
        self.ruta.write_text('{"formato": "otra-cosa"}', encoding="utf-8")
        with self.assertRaises(ErrorBoveda):
            Boveda(self.ruta).desbloquear(MAESTRA)

    def test_archivo_danado(self) -> None:
        self.boveda.bloquear()
        self.ruta.write_text("{esto no es json", encoding="utf-8")
        with self.assertRaises(ErrorBoveda):
            Boveda(self.ruta).desbloquear(MAESTRA)

    def test_archivo_vacio(self) -> None:
        self.boveda.bloquear()
        self.ruta.write_bytes(b"")
        with self.assertRaises(ErrorBoveda):
            Boveda(self.ruta).desbloquear(MAESTRA)


if __name__ == "__main__":
    unittest.main()
