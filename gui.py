from __future__ import annotations

import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any, Callable

import criptografia
from crud import (
    Boveda,
    Credencial,
    ErrorBoveda,
    ErrorClaveIncorrecta,
    ErrorCredencialNoExiste,
)

FUENTE = "Segoe UI"
COLOR_FONDO = "#f3f4f6"
COLOR_PRIMARIO = "#2563eb"
COLOR_PRIMARIO_ACTIVO = "#1d4ed8"
COLOR_TEXTO = "#111827"
COLOR_TEXTO_SUAVE = "#4b5563"
COLOR_BORDE = "#e5e7eb"
COLOR_ERROR = "#b91c1c"
COLOR_EXITO = "#047857"
COLOR_AVISO = "#b45309"

AUTO_BLOQUEO_SEGUNDOS = 300
SEGUNDOS_PORTAPAPELES = 30


def formatear_fecha(iso: str) -> str:
    if not iso:
        return ""
    try:
        momento = datetime.fromisoformat(iso)
    except ValueError:
        return iso
    if momento.tzinfo is not None:
        momento = momento.astimezone()
    return momento.strftime("%d-%m-%Y %H:%M")


def _evaluar_fortaleza(texto: str) -> tuple[str, str]:
    if len(texto) < 8:
        return "Demasiado corta (mínimo 8)", COLOR_ERROR
    clases = sum(
        [
            any(c.islower() for c in texto),
            any(c.isupper() for c in texto),
            any(c.isdigit() for c in texto),
            any(not c.isalnum() for c in texto),
        ]
    )
    if len(texto) >= 14 and clases == 4:
        return "Fuerte", COLOR_EXITO
    if len(texto) >= 10 and clases >= 3:
        return "Aceptable", COLOR_AVISO
    return "Débil: use 12+ caracteres y mezcle tipos", COLOR_ERROR


class Aplicacion(tk.Tk):
    def __init__(self, ruta_boveda: str | Path) -> None:
        super().__init__()
        self.title("Gestor de contraseñas local")
        self.geometry("900x600")
        self.minsize(760, 500)
        self.configure(background=COLOR_FONDO)
        self.option_add("*tearOff", False)

        self.boveda = Boveda(ruta_boveda)
        self._panel: ttk.Frame | None = None
        self._id_auto: str | None = None
        self._id_portapapeles: str | None = None
        self._texto_portapapeles: str | None = None
        self._dialogos_abiertos = 0

        self._configurar_estilo()
        self.report_callback_exception = self._reportar_error
        self.protocol("WM_DELETE_WINDOW", self._al_cerrar)

        self.bind_all("<KeyPress>", self._actividad, add="+")
        self.bind_all("<ButtonPress>", self._actividad, add="+")
        self.bind_all("<Control-n>", self._atajo_nueva)
        self.bind_all("<Control-f>", self._atajo_buscar)
        self.bind_all("<Control-l>", self._atajo_bloquear)

        self._mostrar_acceso()

    def _configurar_estilo(self) -> None:
        estilo = ttk.Style(self)
        try:
            estilo.theme_use("clam")
        except tk.TclError:
            pass

        estilo.configure(".", font=(FUENTE, 10), background=COLOR_FONDO,
                         foreground=COLOR_TEXTO)
        estilo.configure("TFrame", background=COLOR_FONDO)
        estilo.configure("Tarjeta.TFrame", background="white")
        estilo.configure("TLabel", background=COLOR_FONDO, foreground=COLOR_TEXTO)
        estilo.configure("Tarjeta.TLabel", background="white",
                         foreground=COLOR_TEXTO)
        estilo.configure("TarjetaSuave.TLabel", background="white",
                         foreground=COLOR_TEXTO_SUAVE)
        estilo.configure("TarjetaTitulo.TLabel", background="white",
                         foreground=COLOR_TEXTO, font=(FUENTE, 18, "bold"))
        estilo.configure("Titulo.TLabel", font=(FUENTE, 20, "bold"))
        estilo.configure("Subtitulo.TLabel", foreground=COLOR_TEXTO_SUAVE,
                         font=(FUENTE, 10))
        estilo.configure("Error.TLabel", foreground=COLOR_ERROR,
                         background="white")
        estilo.configure("Estado.TLabel", foreground=COLOR_TEXTO_SUAVE,
                         font=(FUENTE, 9))
        estilo.configure("Tarjeta.TCheckbutton", background="white",
                         foreground=COLOR_TEXTO_SUAVE)
        estilo.map("Tarjeta.TCheckbutton",
                   background=[("active", "white")],
                   foreground=[("active", COLOR_TEXTO)])

        estilo.configure("TEntry", fieldbackground="white", padding=(8, 7),
                         bordercolor=COLOR_BORDE, lightcolor=COLOR_BORDE,
                         darkcolor=COLOR_BORDE, insertcolor=COLOR_TEXTO)

        estilo.configure("Acento.TButton", background=COLOR_PRIMARIO,
                         foreground="white", borderwidth=0, relief="flat",
                         padding=(16, 9), font=(FUENTE, 10, "bold"))
        estilo.map(
            "Acento.TButton",
            background=[("pressed", "#1e40af"), ("active", COLOR_PRIMARIO_ACTIVO),
                        ("disabled", "#9ca3af")],
            foreground=[("disabled", "#f3f4f6")],
        )
        estilo.configure("Secundario.TButton", background="#e5e7eb",
                         foreground=COLOR_TEXTO, borderwidth=0, relief="flat",
                         padding=(12, 7))
        estilo.map("Secundario.TButton",
                   background=[("active", "#d1d5db"), ("pressed", "#cbd5e1")])
        estilo.configure("Peligro.TButton", background="#fee2e2",
                         foreground="#991b1b", borderwidth=0, relief="flat",
                         padding=(12, 7))
        estilo.map("Peligro.TButton", background=[("active", "#fecaca")])

        estilo.configure("Treeview", background="white", fieldbackground="white",
                         foreground=COLOR_TEXTO, rowheight=30, borderwidth=0)
        estilo.configure("Treeview.Heading", background="#eef2f7",
                         foreground="#374151", relief="flat",
                         font=(FUENTE, 9, "bold"), padding=(8, 8))
        estilo.map("Treeview.Heading", background=[("active", "#e2e8f0")])
        estilo.map("Treeview",
                   background=[("selected", COLOR_PRIMARIO)],
                   foreground=[("selected", "white")])

    def _cambiar_panel(self, nuevo: ttk.Frame) -> None:
        if self._panel is not None:
            self._panel.destroy()
        self._panel = nuevo
        nuevo.pack(fill="both", expand=True)

    def _mostrar_acceso(self) -> None:
        self._cancelar_auto_bloqueo()
        self._cambiar_panel(PantallaAcceso(self, crear=not self.boveda.existe))

    def _mostrar_principal(self) -> None:
        self._cambiar_panel(PantallaPrincipal(self))
        self._reiniciar_auto_bloqueo()


    def bloquear(self, por_inactividad: bool = False) -> None:
        self.boveda.bloquear()
        self._limpiar_portapapeles()
        self._mostrar_acceso()
        if por_inactividad:
            messagebox.showinfo(
                "Sesión bloqueada",
                "La bóveda se bloqueó tras varios minutos de inactividad.",
                parent=self,
            )

    def _reiniciar_auto_bloqueo(self) -> None:
        self._cancelar_auto_bloqueo()
        self._id_auto = self.after(
            AUTO_BLOQUEO_SEGUNDOS * 1000, self._auto_bloquear
        )

    def _cancelar_auto_bloqueo(self) -> None:
        if self._id_auto is not None:
            try:
                self.after_cancel(self._id_auto)
            except tk.TclError:
                pass
            self._id_auto = None

    def _actividad(self, _evento: tk.Event | None = None) -> None:
        if self.boveda.desbloqueada:
            self._reiniciar_auto_bloqueo()

    def _atajo_nueva(self, _evento: tk.Event | None = None) -> None:
        if self._dialogos_abiertos or not self.boveda.desbloqueada:
            return
        panel = self._panel
        if isinstance(panel, PantallaPrincipal):
            panel._nueva()

    def _atajo_buscar(self, _evento: tk.Event | None = None) -> None:
        if self._dialogos_abiertos or not self.boveda.desbloqueada:
            return
        panel = self._panel
        if isinstance(panel, PantallaPrincipal):
            panel._enfocar_busqueda()

    def _atajo_bloquear(self, _evento: tk.Event | None = None) -> None:
        if self._dialogos_abiertos:
            return
        if self.boveda.desbloqueada:
            self.bloquear()

    def _auto_bloquear(self) -> None:
        self._id_auto = None
        if not self.boveda.desbloqueada:
            return
        if self._dialogos_abiertos:
            self._reiniciar_auto_bloqueo()
            return
        self.bloquear(por_inactividad=True)

    def _al_cerrar(self) -> None:
        self._limpiar_portapapeles()
        self.boveda.bloquear()
        self.destroy()

    def copiar_al_portapapeles(self, texto: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(texto)
        self.update_idletasks()
        self._texto_portapapeles = texto
        if self._id_portapapeles is not None:
            self.after_cancel(self._id_portapapeles)
        self._id_portapapeles = self.after(
            SEGUNDOS_PORTAPAPELES * 1000, self._limpiar_portapapeles
        )

    def _limpiar_portapapeles(self) -> None:
        if self._id_portapapeles is not None:
            try:
                self.after_cancel(self._id_portapapeles)
            except tk.TclError:
                pass
            self._id_portapapeles = None
        try:
            actual = self.clipboard_get()
        except tk.TclError:
            actual = None
        if actual is not None and actual == self._texto_portapapeles:
            try:
                self.clipboard_clear()
            except tk.TclError:
                pass
        self._texto_portapapeles = None

    def registrar_dialogo(self, abierto: bool) -> None:
        self._dialogos_abiertos = max(0, self._dialogos_abiertos + (1 if abierto else -1))

    def _reportar_error(self, tipo: type[BaseException], valor: BaseException,
                        traza: Any) -> None:
        try:
            messagebox.showerror(
                "Error inesperado",
                f"{tipo.__name__}: {valor}",
                parent=self,
            )
        except tk.TclError:
            pass


class PantallaAcceso(ttk.Frame):
    def __init__(self, maestro: Aplicacion, crear: bool) -> None:
        super().__init__(maestro, style="TFrame")
        self.maestro = maestro
        self.crear = crear
        self._intentos = 0
        self._espera_restante = 0

        contenedor = ttk.Frame(self)
        contenedor.place(relx=0.5, rely=0.5, anchor="center")
        tarjeta = tk.Frame(
            contenedor, background="white", highlightbackground=COLOR_BORDE,
            highlightthickness=1, padx=44, pady=36,
        )
        tarjeta.pack()

        ttk.Label(
            tarjeta, text="Gestor de contraseñas local",
            style="TarjetaTitulo.TLabel",
        ).pack(anchor="w")
        ttk.Label(
            tarjeta,
            text="Tus credenciales viajan cifradas en un único archivo local,\n"
                 "sin conexión a internet.",
            style="TarjetaSuave.TLabel", justify="left",
        ).pack(anchor="w", pady=(4, 18))

        if crear:
            self._construir_creacion(tarjeta)
        else:
            self._construir_desbloqueo(tarjeta)

        ttk.Label(
            tarjeta, text=f"Bóveda: {maestro.boveda.ruta}",
            style="TarjetaSuave.TLabel", font=(FUENTE, 8),
        ).pack(anchor="w", pady=(18, 0))

    def _construir_creacion(self, padre: tk.Frame) -> None:
        ttk.Label(padre, text="Crea tu contraseña maestra",
                  style="Tarjeta.TLabel", font=(FUENTE, 10, "bold")).pack(anchor="w")

        self._entrada = self._campo(padre, "Contraseña maestra")
        self._repetida = self._campo(padre, "Repite la contraseña maestra")
        self._entrada.bind("<KeyRelease>", self._actualizar_fortaleza)

        self._fortaleza = ttk.Label(
            padre, text="Mínimo 8 caracteres; se recomienda 12 o más.",
            style="TarjetaSuave.TLabel",
        )
        self._fortaleza.pack(anchor="w", pady=(2, 0))

        self._mostrar = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            padre, text="Mostrar contraseñas", variable=self._mostrar,
            command=self._alternar_visibilidad, style="Tarjeta.TCheckbutton",
        ).pack(anchor="w", pady=(6, 12))

        ttk.Button(
            padre, text="Crear bóveda", style="Acento.TButton",
            command=self._crear_boveda,
        ).pack(fill="x")
        self._error = ttk.Label(padre, text="", style="Error.TLabel",
                                wraplength=340)
        self._error.pack(anchor="w", pady=(10, 0))

        self._entrada.bind("<Return>", lambda _e: self._repetida.focus_set())
        self._repetida.bind("<Return>", lambda _e: self._crear_boveda())
        self._entrada.focus_set()

    def _crear_boveda(self) -> None:
        contrasena = self._entrada.get()
        repetida = self._repetida.get()
        if len(contrasena) < 8:
            self._error.config(
                text="La contraseña maestra debe tener al menos 8 caracteres."
            )
            return
        if contrasena != repetida:
            self._error.config(text="Las dos contraseñas no coinciden.")
            self._repetida.delete(0, "end")
            self._repetida.focus_set()
            return
        try:
            self.maestro.boveda.crear(contrasena)
        except ErrorBoveda as exc:
            self._error.config(text=str(exc))
            return
        self._entrada.delete(0, "end")
        self._repetida.delete(0, "end")
        messagebox.showinfo(
            "Bóveda creada",
            "Guarda tu contraseña maestra en un lugar seguro.\n\n"
            "No se almacena en el disco y, si la olvidas, no hay forma de "
            "recuperar las credenciales.",
            parent=self.maestro,
        )
        self.maestro._mostrar_principal()

    def _construir_desbloqueo(self, padre: tk.Frame) -> None:
        ttk.Label(padre, text="Introduce tu contraseña maestra",
                  style="Tarjeta.TLabel", font=(FUENTE, 10, "bold")).pack(anchor="w")

        self._entrada = self._campo(padre, "Contraseña maestra")
        self._mostrar = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            padre, text="Mostrar contraseña", variable=self._mostrar,
            command=self._alternar_visibilidad, style="Tarjeta.TCheckbutton",
        ).pack(anchor="w", pady=(6, 12))

        self._boton = ttk.Button(
            padre, text="Desbloquear", style="Acento.TButton",
            command=self._desbloquear,
        )
        self._boton.pack(fill="x")
        self._error = ttk.Label(padre, text="", style="Error.TLabel",
                                wraplength=340)
        self._error.pack(anchor="w", pady=(10, 0))

        self._entrada.bind("<Return>", lambda _e: self._desbloquear())
        self._entrada.focus_set()

    def _desbloquear(self) -> None:
        if self._espera_restante > 0:
            return
        contrasena = self._entrada.get()
        if not contrasena:
            self._error.config(text="Escribe la contraseña maestra.")
            return
        try:
            self.maestro.boveda.desbloquear(contrasena)
        except ErrorClaveIncorrecta:
            self._intentos += 1
            self._entrada.delete(0, "end")
            self._error.config(text="Contraseña incorrecta. Inténtalo de nuevo.")
            self._penalizar()
        except ErrorBoveda as exc:
            self._error.config(text=str(exc))
        else:
            self._entrada.delete(0, "end")
            self.maestro._mostrar_principal()

    def _penalizar(self) -> None:#limite intento
        if self._intentos < 3:
            return
        self._espera_restante = min(2 ** (self._intentos - 3), 30)
        self._boton.state(["disabled"])
        self._entrada.state(["disabled"])
        self._actualizar_espera()

    def _actualizar_espera(self) -> None:
        if not self.winfo_exists():
            return
        if self._espera_restante <= 0:
            self._boton.state(["!disabled"])
            self._entrada.state(["!disabled"])
            self._entrada.focus_set()
            return
        self._error.config(
            text=f"Demasiados intentos. Espera {self._espera_restante} s."
        )
        self._espera_restante -= 1
        self.after(1000, self._actualizar_espera)

    def _campo(self, padre: tk.Frame, etiqueta: str) -> ttk.Entry:
        ttk.Label(padre, text=etiqueta, style="Tarjeta.TLabel").pack(
            anchor="w", pady=(10, 4)
        )
        entrada = ttk.Entry(padre, show="•", width=36)
        entrada.pack(anchor="w", fill="x")
        return entrada

    def _alternar_visibilidad(self) -> None:
        mostrar = "" if self._mostrar.get() else "•"
        self._entrada.configure(show=mostrar)
        if self.crear:
            self._repetida.configure(show=mostrar)

    def _actualizar_fortaleza(self, _evento: tk.Event | None = None) -> None:
        etiqueta, color = _evaluar_fortaleza(self._entrada.get())
        self._fortaleza.configure(text=etiqueta, foreground=color)


class PantallaPrincipal(ttk.Frame):
    def __init__(self, maestro: Aplicacion) -> None:
        super().__init__(maestro, style="TFrame", padding=(24, 18))
        self.maestro = maestro
        self.boveda = maestro.boveda
        self._id_seleccionado: str | None = None
        self._id_mensaje: str | None = None

        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        self._construir_cabecera()
        self._construir_barra()
        self._construir_tabla()
        self._construir_pie()
        self.refrescar()

    def _construir_cabecera(self) -> None:
        cabecera = ttk.Frame(self)
        cabecera.grid(row=0, column=0, sticky="ew")
        cabecera.columnconfigure(0, weight=1)

        textos = ttk.Frame(cabecera)
        textos.grid(row=0, column=0, sticky="w")
        ttk.Label(textos, text="Tus credenciales", style="Titulo.TLabel").pack(anchor="w")
        ttk.Label(
            textos,
            text="AES-256-GCM · Argon2id · todo se queda en este equipo",
            style="Subtitulo.TLabel",
        ).pack(anchor="w", pady=(2, 0))

        ttk.Button(
            cabecera, text="Bloquear sesión", style="Secundario.TButton",
            command=lambda: self.maestro.bloquear(),
        ).grid(row=0, column=1, sticky="e")

    def _construir_barra(self) -> None:
        barra = ttk.Frame(self)
        barra.grid(row=1, column=0, sticky="ew", pady=(16, 10))
        barra.columnconfigure(1, weight=1)

        ttk.Label(barra, text="Buscar", style="Estado.TLabel").grid(
            row=0, column=0, padx=(0, 8)
        )
        self._busqueda = tk.StringVar()
        self._busqueda.trace_add("write", lambda *_: self.refrescar())
        self._entrada_busqueda = ttk.Entry(
            barra, textvariable=self._busqueda, width=28
        )
        self._entrada_busqueda.grid(row=0, column=1, sticky="ew", padx=(0, 12))

        acciones = ttk.Frame(barra)
        acciones.grid(row=0, column=2, sticky="e")

        ttk.Button(
            acciones, text="+ Nueva", style="Acento.TButton",
            command=self._nueva,
        ).pack(side="left", padx=(0, 6))
        self._btn_editar = ttk.Button(
            acciones, text="Editar", style="Secundario.TButton",
            command=self._editar,
        )
        self._btn_editar.pack(side="left", padx=(0, 6))
        self._btn_copiar = ttk.Button(
            acciones, text="Copiar", style="Secundario.TButton",
            command=self._copiar,
        )
        self._btn_copiar.pack(side="left", padx=(0, 6))
        self._btn_eliminar = ttk.Button(
            acciones, text="Eliminar", style="Peligro.TButton",
            command=self._eliminar,
        )
        self._btn_eliminar.pack(side="left")

    def _construir_tabla(self) -> None:
        marco = ttk.Frame(self, style="Tarjeta.TFrame")
        marco.grid(row=2, column=0, sticky="nsew")
        marco.columnconfigure(0, weight=1)
        marco.rowconfigure(0, weight=1)

        self._arbol = ttk.Treeview(
            marco, columns=("sitio", "usuario", "modificado"),
            show="headings", selectmode="browse",
        )
        self._arbol.heading("sitio", text="Sitio")
        self._arbol.heading("usuario", text="Usuario")
        self._arbol.heading("modificado", text="Modificado")
        self._arbol.column("sitio", width=300, anchor="w")
        self._arbol.column("usuario", width=220, anchor="w")
        self._arbol.column("modificado", width=140, anchor="w")
        self._arbol.tag_configure("par", background="#f9fafb")
        self._arbol.grid(row=0, column=0, sticky="nsew")

        barra = ttk.Scrollbar(marco, orient="vertical", command=self._arbol.yview)
        barra.grid(row=0, column=1, sticky="ns")
        self._arbol.configure(yscrollcommand=barra.set)

        self._arbol.bind("<<TreeviewSelect>>", lambda _e: self._al_seleccionar())
        self._arbol.bind("<Double-1>", lambda _e: self._editar())
        self._arbol.bind("<Delete>", lambda _e: self._eliminar())
        self._arbol.bind("<Control-c>", lambda _e: self._copiar())

    def _construir_pie(self) -> None:
        pie = ttk.Frame(self)
        pie.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        pie.columnconfigure(0, weight=1)

        self._estado = ttk.Label(pie, text="", style="Estado.TLabel")
        self._estado.grid(row=0, column=0, sticky="w")
        ttk.Label(
            pie, text="Doble clic para editar · Ctrl+N nueva · Ctrl+L bloquear",
            style="Estado.TLabel",
        ).grid(row=0, column=1, sticky="e")

    def refrescar(self) -> None:
        seleccion = self._seleccionado_id()
        for item in self._arbol.get_children():
            self._arbol.delete(item)
        try:
            credenciales = self.boveda.listar(self._busqueda.get())
        except ErrorBoveda:
            return
        for indice, credencial in enumerate(credenciales):
            self._arbol.insert(
                "", "end", iid=credencial.id,
                values=(
                    credencial.sitio,
                    credencial.usuario,
                    formatear_fecha(credencial.modificado),
                ),
                tags=("par",) if indice % 2 else (),
            )
        if seleccion and self._arbol.exists(seleccion):
            self._arbol.selection_set(seleccion)
        self._actualizar_botones()
        self._mostrar_mensaje(f"{len(credenciales)} credencial(es)")

    def _seleccionado_id(self) -> str | None:
        seleccion = self._arbol.selection()
        return seleccion[0] if seleccion else None

    def _seleccionar(self, identificador: str) -> None:
        if self._arbol.exists(identificador):
            self._arbol.selection_set(identificador)
            self._arbol.focus(identificador)
            self._arbol.see(identificador)
        self._actualizar_botones()

    def _al_seleccionar(self) -> None:
        self._id_seleccionado = self._seleccionado_id()
        self._actualizar_botones()

    def _actualizar_botones(self) -> None:
        estado = ["!disabled"] if self._seleccionado_id() else ["disabled"]
        for boton in (self._btn_editar, self._btn_copiar, self._btn_eliminar):
            boton.state(estado)

    def _mostrar_mensaje(self, texto: str, temporal: bool = False) -> None:
        if temporal and self._id_mensaje is not None:
            try:
                self.after_cancel(self._id_mensaje)
            except tk.TclError:
                pass
            self._id_mensaje = None
        self._estado.config(text=texto)
        if temporal:
            self._id_mensaje = self.after(
                6000, lambda: self._estado.config(text="")
            )

    def _enfocar_busqueda(self) -> None:
        self._entrada_busqueda.focus_set()
        self._entrada_busqueda.select_range(0, "end")

    def _nueva(self) -> None:
        self._abrir_dialogo(None)

    def _editar(self) -> None:
        identificador = self._seleccionado_id()
        if not identificador:
            return
        try:
            credencial = self.boveda.obtener(identificador)
        except ErrorCredencialNoExiste:
            self.refrescar()
            return
        self._abrir_dialogo(credencial)

    def _copiar(self) -> None:
        identificador = self._seleccionado_id()
        if not identificador:
            return
        try:
            credencial = self.boveda.obtener(identificador)
        except ErrorCredencialNoExiste:
            self.refrescar()
            return
        self.maestro.copiar_al_portapapeles(credencial.contrasena)
        self._mostrar_mensaje(
            f"Contraseña de «{credencial.sitio}» copiada; se borrará en "
            f"{SEGUNDOS_PORTAPAPELES} s.",
            temporal=True,
        )

    def _eliminar(self) -> None:
        identificador = self._seleccionado_id()
        if not identificador:
            return
        try:
            credencial = self.boveda.obtener(identificador)
        except ErrorCredencialNoExiste:
            self.refrescar()
            return
        if not messagebox.askyesno(
            "Eliminar credencial",
            f"¿Eliminar la credencial de «{credencial.sitio}»?\n\n"
            "Esta acción no se puede deshacer.",
            parent=self.maestro,
        ):
            return
        try:
            self.boveda.eliminar_credencial(identificador)
        except ErrorBoveda as exc:
            messagebox.showerror("No se pudo eliminar", str(exc), parent=self.maestro)
            return
        self.refrescar()
        self._mostrar_mensaje("Credencial eliminada.", temporal=True)

    def _abrir_dialogo(self, credencial: Credencial | None) -> None:
        def al_guardar(datos: dict[str, str]) -> None:
            if credencial is None:
                nueva = self.boveda.crear_credencial(**datos)
                identificador = nueva.id
                mensaje = "Credencial creada."
            else:
                self.boveda.actualizar_credencial(credencial.id, **datos)
                identificador = credencial.id
                mensaje = "Credencial actualizada."
            self.refrescar()
            self._seleccionar(identificador)
            self._mostrar_mensaje(mensaje, temporal=True)
        DialogoCredencial(self.maestro, credencial, al_guardar)


class DialogoCredencial(tk.Toplevel):
    def __init__(
        self,
        maestro: Aplicacion,
        credencial: Credencial | None,
        al_guardar: Callable[[dict[str, str]], None],
    ) -> None:
        super().__init__(maestro)
        self.maestro = maestro
        self._al_guardar = al_guardar
        self._credencial = credencial
        self._cerrado = False

        self.title("Editar credencial" if credencial else "Nueva credencial")
        self.configure(background=COLOR_FONDO)
        self.resizable(False, False)
        self.transient(maestro)
        self.protocol("WM_DELETE_WINDOW", self._cerrar)
        self.bind("<Escape>", lambda _e: self._cerrar())
        maestro.registrar_dialogo(True)

        self._construir()
        self.update_idletasks()
        self._centrar()
        self.wait_visibility()
        self.grab_set()
        self._sitio.focus_set()

    def _construir(self) -> None:
        marco = tk.Frame(
            self, background="white", highlightbackground=COLOR_BORDE,
            highlightthickness=1, padx=28, pady=24,
        )
        marco.pack(fill="both", expand=True, padx=16, pady=16)

        ttk.Label(
            marco,
            text="Editar credencial" if self._credencial else "Nueva credencial",
            style="TarjetaTitulo.TLabel", font=(FUENTE, 15, "bold"),
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 16))

        ttk.Label(marco, text="Sitio *", style="Tarjeta.TLabel").grid(
            row=1, column=0, sticky="w", pady=(0, 4)
        )
        self._sitio = ttk.Entry(marco, width=36)
        self._sitio.grid(row=2, column=0, columnspan=3, sticky="ew")

        ttk.Label(marco, text="Usuario *", style="Tarjeta.TLabel").grid(
            row=3, column=0, sticky="w", pady=(12, 4)
        )
        self._usuario = ttk.Entry(marco, width=36)
        self._usuario.grid(row=4, column=0, columnspan=3, sticky="ew")

        ttk.Label(marco, text="Contraseña *", style="Tarjeta.TLabel").grid(
            row=5, column=0, sticky="w", pady=(12, 4)
        )
        self._contrasena = ttk.Entry(marco, show="•", width=34)
        self._contrasena.grid(row=6, column=0, sticky="ew", columnspan=2)
        self._mostrar = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            marco, text="Mostrar", variable=self._mostrar,
            command=self._alternar_visibilidad, style="Tarjeta.TCheckbutton",
        ).grid(row=6, column=2, sticky="w", padx=(8, 0))
        ttk.Button(
            marco, text="Generar contraseña", style="Secundario.TButton",
            command=self._generar,
        ).grid(row=7, column=0, sticky="w", pady=(8, 0))

        ttk.Label(marco, text="Notas", style="Tarjeta.TLabel").grid(
            row=8, column=0, sticky="w", pady=(14, 4)
        )
        self._notas = tk.Text(
            marco, width=44, height=4, wrap="word", font=(FUENTE, 10),
            background="white", foreground=COLOR_TEXTO, relief="flat",
            highlightthickness=1, highlightbackground=COLOR_BORDE,
            highlightcolor=COLOR_PRIMARIO, padx=8, pady=6,
        )
        self._notas.grid(row=9, column=0, columnspan=3, sticky="ew")

        self._error = ttk.Label(marco, text="", style="Error.TLabel",
                                wraplength=400)
        self._error.grid(row=10, column=0, columnspan=3, sticky="w", pady=(10, 0))

        botones = ttk.Frame(marco, style="Tarjeta.TFrame")
        botones.grid(row=11, column=0, columnspan=3, sticky="e", pady=(18, 0))
        ttk.Button(
            botones, text="Cancelar", style="Secundario.TButton",
            command=self._cerrar,
        ).pack(side="left", padx=(0, 8))
        ttk.Button(
            botones, text="Guardar", style="Acento.TButton",
            command=self._guardar,
        ).pack(side="left")

        if self._credencial is not None:
            self._sitio.insert(0, self._credencial.sitio)
            self._usuario.insert(0, self._credencial.usuario)
            self._contrasena.insert(0, self._credencial.contrasena)
            self._notas.insert("1.0", self._credencial.notas)

        self._sitio.bind("<Return>", lambda _e: self._usuario.focus_set())
        self._usuario.bind("<Return>", lambda _e: self._contrasena.focus_set())
        self._contrasena.bind("<Return>", lambda _e: self._guardar())

    def _alternar_visibilidad(self) -> None:
        self._contrasena.configure(show="" if self._mostrar.get() else "•")

    def _generar(self) -> None:
        self._contrasena.delete(0, "end")
        self._contrasena.insert(0, criptografia.generar_contrasena(20))
        self._mostrar.set(True)
        self._alternar_visibilidad()

    def _guardar(self) -> None:
        datos = {
            "sitio": self._sitio.get(),
            "usuario": self._usuario.get(),
            "contrasena": self._contrasena.get(),
            "notas": self._notas.get("1.0", "end-1c"),
        }
        if not datos["sitio"].strip():
            self._error.config(text="El sitio no puede estar vacío.")
            self._sitio.focus_set()
            return
        if not datos["usuario"].strip():
            self._error.config(text="El usuario no puede estar vacío.")
            self._usuario.focus_set()
            return
        if not datos["contrasena"]:
            self._error.config(text="La contraseña no puede estar vacía.")
            self._contrasena.focus_set()
            return
        try:
            self._al_guardar(datos)
        except ErrorBoveda as exc:
            self._error.config(text=str(exc))
            return
        self._cerrar()

    def _centrar(self) -> None:
        ancho = self.winfo_reqwidth()
        alto = self.winfo_reqheight()
        x = self.master.winfo_rootx() + (self.master.winfo_width() - ancho) // 2
        y = self.master.winfo_rooty() + (self.master.winfo_height() - alto) // 2
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")

    def _cerrar(self) -> None:
        if self._cerrado:
            return
        self._cerrado = True
        self.maestro.registrar_dialogo(False)
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()
