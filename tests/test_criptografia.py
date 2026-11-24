from __future__ import annotations

import unittest

import criptografia as cripto

PARAMETROS_RAPIDOS = cripto.ParametrosKDF(time_cost=1, memory_cost=8192, parallelism=1)
SALT = b"\x11" * cripto.LONGITUD_SALT


class PruebasDerivacion(unittest.TestCase):
    def test_derivacion_es_determinista(self) -> None:
        clave_1 = cripto.derivar_clave("ClaveMaestra123!", SALT, PARAMETROS_RAPIDOS)
        clave_2 = cripto.derivar_clave("ClaveMaestra123!", SALT, PARAMETROS_RAPIDOS)
        self.assertEqual(bytes(clave_1), bytes(clave_2))
        self.assertEqual(len(clave_1), cripto.LONGITUD_CLAVE)

    def test_salt_distinto_da_clave_distinta(self) -> None:
        otra = cripto.derivar_clave(
            "ClaveMaestra123!", b"\x22" * cripto.LONGITUD_SALT, PARAMETROS_RAPIDOS
        )
        base = cripto.derivar_clave("ClaveMaestra123!", SALT, PARAMETROS_RAPIDOS)
        self.assertNotEqual(bytes(base), bytes(otra))

    def test_contrasena_distinta_da_clave_distinta(self) -> None:
        otra = cripto.derivar_clave("OtraClave456!", SALT, PARAMETROS_RAPIDOS)
        base = cripto.derivar_clave("ClaveMaestra123!", SALT, PARAMETROS_RAPIDOS)
        self.assertNotEqual(bytes(base), bytes(otra))

    def test_normalizacion_unicode(self) -> None:
        compuesta = cripto.normalizar_contrasena("contrase\u00f1a")
        descompuesta = cripto.normalizar_contrasena("contrasen\u0303a")
        self.assertEqual(compuesta, descompuesta)

    def test_salt_de_longitud_incorrecta(self) -> None:
        with self.assertRaises(cripto.ErrorCriptografico):
            cripto.derivar_clave("ClaveMaestra123!", b"corto", PARAMETROS_RAPIDOS)

    def test_contrasena_vacia(self) -> None:
        with self.assertRaises(cripto.ErrorCriptografico):
            cripto.normalizar_contrasena("")

    def test_generar_salt_es_aleatorio(self) -> None:
        salts = {cripto.generar_salt() for _ in range(20)}
        self.assertEqual(len(salts), 20)
        self.assertTrue(all(len(s) == cripto.LONGITUD_SALT for s in salts))


class PruebasParametrosKDF(unittest.TestCase):
    def test_valores_por_defecto(self) -> None:
        parametros = cripto.ParametrosKDF()
        self.assertEqual(parametros.time_cost, 3)
        self.assertEqual(parametros.memory_cost, 65536)
        self.assertEqual(parametros.parallelism, 4)
        self.assertEqual(parametros.hash_len, 32)

    def test_rechaza_valores_fuera_de_rango(self) -> None:
        for kwargs in (
            {"time_cost": 0},
            {"time_cost": 100},
            {"memory_cost": 1},
            {"parallelism": 0},
            {"hash_len": 16},
            {"memory_cost": 8, "parallelism": 4},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    cripto.ParametrosKDF(**kwargs)

    def test_ida_y_vuelta(self) -> None:
        parametros = cripto.ParametrosKDF(time_cost=2, memory_cost=16384, parallelism=2)
        recuperados = cripto.ParametrosKDF.desde_diccionario(
            parametros.a_diccionario()
        )
        self.assertEqual(parametros, recuperados)

    def test_rechaza_algoritmo_desconocido(self) -> None:
        datos = cripto.ParametrosKDF().a_diccionario()
        datos["algoritmo"] = "scrypt"
        with self.assertRaises(cripto.ErrorCriptografico):
            cripto.ParametrosKDF.desde_diccionario(datos)

    def test_rechaza_booleanos_y_texto(self) -> None:
        for valor in (True, "3", 3.5, None):
            datos = cripto.ParametrosKDF().a_diccionario()
            datos["time_cost"] = valor
            with self.subTest(valor=valor):
                with self.assertRaises(cripto.ErrorCriptografico):
                    cripto.ParametrosKDF.desde_diccionario(datos)


class PruebasCifrado(unittest.TestCase):
    def setUp(self) -> None:
        self.clave = cripto.derivar_clave(
            "ClaveMaestra123!", SALT, PARAMETROS_RAPIDOS
        )

    def tearDown(self) -> None:
        cripto.limpiar_clave(self.clave)

    def test_ida_y_vuelta(self) -> None:
        nonce, cifrado = cripto.cifrar(self.clave, b"secreto", b"contexto")
        self.assertEqual(len(nonce), cripto.LONGITUD_NONCE)
        self.assertEqual(
            cripto.descifrar(self.clave, nonce, cifrado, b"contexto"), b"secreto"
        )

    def test_el_texto_cifrado_incluye_la_etiqueta(self) -> None:
        _, cifrado = cripto.cifrar(self.clave, b"x")
        self.assertEqual(len(cifrado), 1 + cripto.LONGITUD_ETIQUETA)

    def test_nonce_es_nuevo_en_cada_cifrado(self) -> None:
        nonce_1, _ = cripto.cifrar(self.clave, b"igual")
        nonce_2, _ = cripto.cifrar(self.clave, b"igual")
        self.assertNotEqual(nonce_1, nonce_2)

    def test_texto_alterado_falla(self) -> None:
        nonce, cifrado = cripto.cifrar(self.clave, b"secreto")
        alterado = bytes([cifrado[0] ^ 0x01]) + cifrado[1:]
        with self.assertRaises(cripto.ErrorIntegridad):
            cripto.descifrar(self.clave, nonce, alterado)

    def test_aad_distinto_falla(self) -> None:
        nonce, cifrado = cripto.cifrar(self.clave, b"secreto", b"a")
        with self.assertRaises(cripto.ErrorIntegridad):
            cripto.descifrar(self.clave, nonce, cifrado, b"b")

    def test_clave_incorrecta_falla(self) -> None:
        nonce, cifrado = cripto.cifrar(self.clave, b"secreto")
        otra = cripto.derivar_clave("OtraClave456!", SALT, PARAMETROS_RAPIDOS)
        with self.assertRaises(cripto.ErrorIntegridad):
            cripto.descifrar(otra, nonce, cifrado)

    def test_nonce_de_longitud_incorrecta(self) -> None:
        _, cifrado = cripto.cifrar(self.clave, b"secreto")
        with self.assertRaises(cripto.ErrorIntegridad):
            cripto.descifrar(self.clave, b"corto", cifrado)

    def test_texto_cifrado_demasiado_corto(self) -> None:
        with self.assertRaises(cripto.ErrorIntegridad):
            cripto.descifrar(
                self.clave, b"\x00" * cripto.LONGITUD_NONCE, b"abc"
            )


class PruebasGenerador(unittest.TestCase):
    def test_longitud_y_clases(self) -> None:
        for longitud in (8, 12, 20, 64, 128):
            with self.subTest(longitud=longitud):
                clave = cripto.generar_contrasena(longitud)
                self.assertEqual(len(clave), longitud)
                self.assertTrue(any(c.islower() for c in clave))
                self.assertTrue(any(c.isupper() for c in clave))
                self.assertTrue(any(c.isdigit() for c in clave))
                self.assertTrue(any(not c.isalnum() for c in clave))

    def test_sin_simbolos(self) -> None:
        clave = cripto.generar_contrasena(30, usar_simbolos=False)
        self.assertTrue(clave.isalnum())

    def test_sin_caracteres_ambiguos(self) -> None:
        ambiguos = set("0Oo1lI")
        for _ in range(50):
            self.assertFalse(ambiguos & set(cripto.generar_contrasena(40)))

    def test_dos_generaciones_no_coinciden(self) -> None:
        self.assertNotEqual(
            cripto.generar_contrasena(32), cripto.generar_contrasena(32)
        )

    def test_longitudes_invalidas(self) -> None:
        for longitud in (7, 129, 0, -1):
            with self.subTest(longitud=longitud):
                with self.assertRaises(cripto.ErrorCriptografico):
                    cripto.generar_contrasena(longitud)
        with self.assertRaises(cripto.ErrorCriptografico):
            cripto.generar_contrasena(True)

    def test_limpiar_clave_sobrescribe(self) -> None:
        clave = bytearray(b"secreto")
        cripto.limpiar_clave(clave)
        self.assertEqual(clave, bytearray(len(b"secreto")))
        cripto.limpiar_clave(None)


if __name__ == "__main__":
    unittest.main()
