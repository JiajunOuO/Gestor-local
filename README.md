# Gestor de contraseñas local

Gestor de credenciales 100 % local escrito en Python 3. Guarda las contraseñas
cifradas en disco y las protege con una única contraseña maestra; no usa la red
en ningún momento, así que no hay servidores de terceros ni superficie de ataque
asociada a una conexión.

- **Derivación de la clave maestra:** Argon2id (con *salt* aleatorio).
- **Cifrado de cada credencial:** AES-256-GCM.
- **Detección de manipulaciones:** HMAC-SHA256 sobre el encabezado y la lista de
  credenciales. Si el archivo se modifica, se reordena o se borra una entrada,
  la bóveda se niega a abrirse.

## Requisitos

- Python 3.10 o superior (probado con 3.12).
- Tkinter.
- `argon2-cffi` y `cryptography` (ver `requirements.txt`).

## Instalación

```powershell
python -m pip install -r requirements.txt
```

## Uso

```powershell
python main.py
```

La primera vez se pide crear la contraseña maestra (mínimo 8 caracteres), a
partir de ahí se pide al iniciar. Por defecto la bóveda se guarda en
`~/.gestor-contrasenas/boveda.json`. Para usar otra ubicación, por ejemplo:

```powershell
python main.py --boveda "D:\respaldo\boveda.json"
```

### Flujo de la aplicación

1. Al iniciar, si no existe la bóveda se ofrece crear la contraseña maestra.
2. Se pide la contraseña maestra, si es incorrecta se puede volver a intentar.
3. Con la bóveda abierta se ve la lista de credenciales y se pueden crear,
   leer, actualizar y eliminar entradas.

Además, la aplicación se bloquea sola tras 5 minutos sin actividad.


## Pruebas

```powershell
python -m unittest discover -s tests -t . -v
```

## Evaluación

Los dos experimento se ejecutan desde la raíz del proyecto y solo imprimen sus
resultados en la terminal:

```powershell
python experimento1.py
python experimento2.py
```
Nota: los resultado puede variar cada vez