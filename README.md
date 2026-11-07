# 📶 Escáner de mi WiFi

Web sencilla para ver qué dispositivos están conectados a tu red WiFi, con información de cada uno y una estimación aproximada de lo cerca que están.

Todo en un solo archivo (`app.py`), sin dependencias: solo Python 3.

## Uso

```bash
python3 app.py
```

Abre http://localhost:8000 y pulsa **Escanear** (tarda alrededor de un minuto).

Para usar otro puerto: `python3 app.py --port 9000`

## Qué hace

- **Lista los dispositivos conectados**: IP, MAC, fabricante, nombre en la red y servicios abiertos.
- **Adivina el tipo de dispositivo**: móvil, Mac, PC, impresora, cámara, Chromecast, Smart TV, IoT…
- **Estima la proximidad** (muy cerca / cerca / media / lejos) y la muestra en un mapa circular.
- **Calcula la distancia aproximada a tu router** con la señal real (RSSI) de tu WiFi.
- **Escaneo automático** cada X minutos.
- **Avisa de dispositivos nuevos** en la web y con una notificación de macOS.
- **Nombres personalizados** para tus dispositivos (✏️).
- **Historial** de conexiones y desconexiones, y lista de dispositivos desconectados.

## Requisitos

- macOS (usa `ping`, `arp`, `route`, `ifconfig`, `system_profiler` y `osascript`).
- Python 3.8 o superior.

## Limitaciones

- **La proximidad es solo orientativa.** Desde un ordenador no se puede medir la señal que recibe el router de cada dispositivo, así que se estima con la latencia, el jitter y la pérdida de paquetes. Para datos más precisos, mira la lista de clientes en el panel de tu router.
- Una desconexión puede tardar hasta unos 20 minutos en detectarse, porque macOS guarda un rato la tabla ARP.
- Los móviles con **MAC privada** no muestran el fabricante.
- El escaneo automático solo funciona mientras `app.py` esté en marcha.

## Privacidad

- El servidor solo escucha en `127.0.0.1`: otros dispositivos de la red no pueden abrir la web.
- Para saber el fabricante se envía **solo el prefijo de la MAC** (los 3 primeros bytes, que identifican al fabricante) a [api.macvendors.com](https://macvendors.com). El resultado se guarda en `vendor_cache.json` para no repetir consultas.
- Los datos de tu red se guardan en local, en `devices_db.json` y `vendor_cache.json`. Ninguno de los dos se sube al repositorio (están en `.gitignore`).

## Aviso

Úsalo solo en redes que sean tuyas o en las que tengas permiso para escanear.
