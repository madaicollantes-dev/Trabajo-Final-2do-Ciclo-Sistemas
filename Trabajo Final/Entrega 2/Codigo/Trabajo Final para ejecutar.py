# ==============================================================================
# 1. IMPORTACIÓN DE LIBRERÍAS
# ==============================================================================
import logging                           # Para guardar registro de eventos (logs)
import smtplib                           # Para enviar correos electrónicos
import time                              # Para manejar tiempos y pausas
import os                                # Para limpiar pantalla del sistema
import psutil                            # Para leer el tráfico de la tarjeta de red
import csv                               # Para leer y escribir archivos en formato csv
import datetime                          # Para manejar y realizar operaciones con el tiempo fechas, horas, minutos y segundos
import socket                            # Para acceder a la tarjeta de red y obtener la ip local
import pandas as pd                      # Para analisis y manipulacion, lee y organiza inteligentemente los datos para el grafico
import mimetypes                         # Para identificar el tipo de imagen del logo y adjuntarlo al correo
import matplotlib.pyplot as plt          # Para creacion de graficos
from email.message import EmailMessage   # Para dar formato al correo
from scapy.all import sniff, ARP, conf   # Scapy: El núcleo del análisis de red
from PIL import Image                    # Pillow: Para procesar la imagen del logo
# ==============================================================================
# 2. CONFIGURACIONES Y COLORES
# ==============================================================================
ROJO = '\033[91m'             # Secuencias de escape ANSI todos inician con \033[
VERDE = '\033[92m'            # \033: Indica que no es un texto para imprimir, si no una instruccion que seguir 
AMARILLO = '\033[93m'         # [: inicia la instruccion
AZUL = '\033[94m'             # numero XX:en este caso el 94 indica color azul y m indica negrita 
RESET = '\033[0m'             # en este caso el 0m apaga todos los efectos
NEGRITA = '\033[1m'
ANCHO_CONSOLA = 60            # Ancho consola sirve para definir un tamaño de referencia y poder definir un centro

# --- CONFIGURACIÓN DE CORREO ---
SMTP_SERVER = "smtp.gmail.com"               #Si usas google como correo de envio dejalo asi
SMTP_PORT = 587                              #Si usas google como correo de envio dejalo asi
EMAIL_USER = "coblitasv2@gmail.com"          #Colocar el correo desde el que enviaras las alertas
EMAIL_PASS = "nyaj rouc jenj usuj"           #Colocar la contraseña de la API (no la del correo)
EMAIL_DESTINO = "u202514590@upc.edu.pe"      #Colocar el correo del profe
NOMBRE_LOGO = "descarga.png"                 #La imagen que se usará en la firma y logo de caratula

# --- CONFIGURACIÓN DE RED ---
IP_MAC_CONFIANZA = {
    "192.168.100.1" : "3c:93:f4:a2:31:24", #Reemplazar por la ip y mac de su router o gateway
    "192.168.100.74": "a8:3b:76:19:07:dd", #Reemplazar por la ip y mac de su laptop o PC desde la que ejecutaran el codigo
    "192.168.100.79": "a0:b1:c2:d3:e4:f5"  #Reemplazar por la ip de un equipo cualquiera que este conectado a la red la mac puede ser cualquiera (debe ser falsa) ya que esto activiara las alertas 
}
NOMBRE_INTERFAZ = "Wi-Fi" #Colocar el nombre de su interface de red Sea Wifi o Eth

# --- CONFIGURACIÓN DE ALERTAS ---
TIEMPO_ENTRE_ALERTAS = 10     # Define el tiempo de cooldown en segundos para alertas de ataques. Sin esto recibiría 5,000 correos en un minuto y bloquearía mi bandeja de entrada
TIEMPO_ENTRE_ALERTAS_BW = 60  # Se configura en 60 (1 minuto). Si fuera muy corto (ej. 10s), recibirías un correo nuevo cada 10 segundos 
UMBRAL_MBPS = 100             # Es el límite de velocidad (en Megabits por segundo) que consideramos "peligroso" o "anormal"

# Variables de estado
ultima_alerta_arp = 0         # Esas variables se inicializan en 0 para representar "El inicio de los tiempos" 
ultima_alerta_bw = 0          # Nunca he enviado una alerta antes

#logging = libreria de registro de eventos
logging.basicConfig(filename='seguridad_sistema.log', level=logging.WARNING, 
                    format='%(asctime)s - %(message)s')
#filename='seguridad_sistema.log': Le dice al programa: "No imprimas los errores solo en la pantalla; guárdalos en este archivo de texto". Si el archivo no existe, lo crea
#level=level=logging.WARNING: Es el filtro de importancia. Le dice al sistema: "Ignora los mensajes informativos (INFO) o de depuración (DEBUG). Solo guarda cosas importantes como Advertencias (WARNING)
#format='%(asctime)s - %(message)s': Define cómo se ve cada línea en el archivo de texto

#Estas dos líneas configuran conf, que es la configuración global de la librería Scapy
conf.verb = 0       # Modo silencioso para scapy. Evita que ensucie la interface grafica con spam de anuncios de monitoreo
conf.resolve = []   # Desactivamos el DNS para agilizar el escaneo

#Estas dos lineas definen el nombre y formato de los archivos que generaremos al monitorear el ancho de banda
ARCHIVO_CSV = 'historial_trafico.csv'
ARCHIVO_IMG = 'grafico_trafico.png'

# ==============================================================================
# 3. FUNCIONES AUXILIARES (UI y NET)
# ==============================================================================
def limpiar_pantalla():
    # Pregunta: "¿Estoy en Windows ('nt')?"
    if os.name == 'nt': os.system('cls') # Si es sí, usa el comando de limpieza de Windows.
    else: os.system('clear') # Si es no (Mac o Linux), usa el comando de ellos.

def convertir_bytes(peso):
    # Revisa cada "byte" disponible: Bytes, KiloBytes, MegaBytes, GigaBytes
    for unidad in ['B', 'KB', 'MB', 'GB']:
        # Si el tamaño es pequeño (menor a 1024), se queda con esa unidad.
        if peso < 1024.0:                
            return f"{peso:.2f} {unidad}" # Devuelve el número con 2 decimales (ej. 10.50 MB)
        # Si es muy grande, lo divide entre 1024 para pasar a la siguiente unidad.
        # Ejemplo: 2048 Bytes / 1024 = 2 KB
        peso /= 1024.0

def obtener_ip_local():
    """Obtiene la IP real de la máquina."""
    # Crea un socket para conectarse a internet.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Intenta conectar con el DNS de Google (8.8.8.8).
        # Nota: No envía datos reales, solo establece la intención de ruta.
        s.connect(('8.8.8.8', 1))
        # Le pregunta al sistema: "¿Qué IP usaste para intentar esta conexión?"
        IP = s.getsockname()[0]
    except Exception:
        # Si no tienes internet o falla, asume que eres "localhost" (127.0.0.1)
        IP = '127.0.0.1' #Esta ip es del localhost no debe modificarse 
    finally:
        # Cierra el socket para no gastar recursos.
        s.close()
    return IP

def crear_caratula(ruta_imagen, ancho_logo=30):
    limpiar_pantalla()  # Borra la pantalla primero
    logo_ascii = []     # Lista vacía donde guardaremos el logo
    try:
        img = Image.open(ruta_imagen)  # Abre la imagen desde el archivo
        # --- Matemáticas de proporción ---
        # Calcula qué tan alta es la imagen comparada con su ancho
        ancho_orig, alto_orig = img.size
        relacion = alto_orig / ancho_orig
        # Calcula la nueva altura. Se multiplica por 0.55 porque las letras en 
        # la consola son rectangulares (altas), no cuadradas. Esto evita que el logo se vea estirado
        alto_logo = int(ancho_logo * relacion * 0.55)
        img = img.resize((ancho_logo, alto_logo)).convert("L")              # Redimensiona la imagen y la convierte a Blanco y Negro ("L")
        pixeles = img.getdata()                        # Obtiene todos los puntos (píxeles) de la imagen
        cadena_ascii = "".join([" " if p > 150 else "█" for p in pixeles])  # Si el punto es blanco (>150), pon un espacio. Si es oscuro, pon un bloque "█"
        logo_ascii = [cadena_ascii[i:i+ancho_logo] for i in range(0, len(cadena_ascii), ancho_logo)] # Corta la cadena larga en líneas para formar el cuadrado del dibujo
    except Exception: pass             # Si la imagen falla, no hace nada y sigue (no rompe el programa)

    # --- Impresión del Texto ---
    # .center() centra el texto en la pantalla basándose en el ancho definido
    print("\n" + "=" * ANCHO_CONSOLA)
    print(f"{NEGRITA}{'TRABAJO FINAL: FUNDAMENTOS DE PROGRAMACIÓN'.center(ANCHO_CONSOLA)}{RESET}")
    print("-" * ANCHO_CONSOLA)
    print("Profesor: Luis Castillo Mesias".center(ANCHO_CONSOLA))
    print("NRC:803".center(ANCHO_CONSOLA))
    print("Carrera de Ingeniería de Redes y Comunicaciones".center(ANCHO_CONSOLA))
    print(" " * ANCHO_CONSOLA)
    print("Grupo 3".center(ANCHO_CONSOLA))
    print("Integrantes: \n -Carlos Jesus Oblitas Vargas\n -Madai Gonzales Collantes\n -Raphael Enrique Avalos Espinoza\n -Bils Ortega Buitron".center(ANCHO_CONSOLA))
    print("-" * ANCHO_CONSOLA)
    print("Universidad Peruana de Ciencias Aplicadas".center(ANCHO_CONSOLA))
    if logo_ascii:   # Si logramos crear el logo, lo imprimimos línea por línea en ROJO
        print(" " * ANCHO_CONSOLA)
        for linea in logo_ascii: print(ROJO + linea.center(ANCHO_CONSOLA) + RESET)
        print(" " * ANCHO_CONSOLA)
    print("-" * ANCHO_CONSOLA)
    print(f"{ROJO}{NEGRITA}{'EXÍGETE, INNOVA'.center(ANCHO_CONSOLA)}{RESET}")
    print(f"{ROJO}{NEGRITA}{'UPC'.center(ANCHO_CONSOLA)}{RESET}")
    print("=" * ANCHO_CONSOLA + "\n")

def mostrar_menu():
    print(f"{NEGRITA}--- MENÚ PRINCIPAL DE MONITOREO ---{RESET}")
    print(f"{VERDE}[1]{RESET} Detección de ARP Spoofing")
    print(f"{VERDE}[2]{RESET} Monitor de Ancho de Banda")
    print(f"{VERDE}[3]{RESET} Ver reporte de logs")
    print(f"{ROJO}[4] Salir{RESET}")
    print("-" * 40)

# --- FUNCIÓN DE CORREO ---
def enviar_email(asunto, cuerpo_texto, ruta_imagen):
    """
    Envía correo HTML con imagen incrustada (firma) al final.
    """
    try:
        # Prepara el mensaje del correo
        msg = EmailMessage()
        msg['Subject'] = asunto
        msg['From'] = EMAIL_USER
        msg['To'] = EMAIL_DESTINO

        # 1. Versión Texto Plano por si el correo no soporta HTML (precaucion extrema)
        msg.set_content(cuerpo_texto) 

        # 2. Versión HTML (Diseño Mejorado)
        # Reemplazamos saltos de línea \n por <br>
        texto_html = cuerpo_texto.replace('\n', '<br>')
        # Crea el código HTML. Fíjate en <img src="cid:logo_upc">.
        # "cid" significa Content-ID. Es como decirle al correo:
        # Aquí va una imagen que te adjunto más abajo con el nombre 'logo_upc'
        html_content = f"""
        <html>
            <body style="font-family: Arial, sans-serif; color: #333;">
                <p>{texto_html}</p>
                <br>
                <img src="cid:logo_upc" alt="Logo UPC" width="150">
            </body>
        </html>
        """
        msg.add_alternative(html_content, subtype='html') # Agrega esta versión HTML al mensaje

        # 3. Adjuntar el logo como firma
        try:
            # Abre el archivo de la imagen en modo lectura binaria ('rb')
            with open(ruta_imagen, 'rb') as img:
                img_data = img.read()
                maintype, subtype = mimetypes.guess_type(ruta_imagen)[0].split('/') # Verifica si es png o jpg
                # Esto adjunta la imagen pero la vincula al ID 'logo_upc'
                # para que aparezca DENTRO del texto y no como archivo adjunto aparte.
                msg.get_payload()[1].add_related(img_data, maintype=maintype, subtype=subtype, cid='logo_upc')
        except FileNotFoundError:
            print(f" >> [AVISO] No se encontró {ruta_imagen}, se enviará sin logo.")
        
        # 4. Enviar
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=5)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)
        server.quit()
        return True

    except Exception as e:
        print(f" >> [ERROR EMAIL] {e}")
        return False

# ==============================================================================
# 4. MÓDULO ARP SPOOFING
# ==============================================================================
def enviar_alerta_arp(ip, mac_falsa, mac_real):
    """
    Función encargada de redactar el correo de alerta con formato HTML.
    NO detecta el ataque, solo reporta lo que 'analizar_paquete_arp' encontró.
    """
    # Averiguamos desde qué computadora (IP) estamos vigilando para ponerlo en el informe
    mi_ip = obtener_ip_local()

    # Preparamos el cuerpo del mensaje
    # Usamos \n para los saltos de línea (la función de envío los convertirá a <br>)
    # Usamos etiquetas HTML <span> y <strong> para los colores y negritas.
    cuerpo = (f"<strong>ALERTA DE SEGURIDAD ARP</strong>\n\n"
              f"Reportado por el equipo: {mi_ip}\n"
              f"-----------------------------------\n"
              f"IP Objetivo: {ip}\n"
              f"MAC Intruso: <span style='color:red; font-weight:bold'>{mac_falsa}</span>\n"
              f"MAC Real: <span style='color:green; font-weight:bold'>{mac_real}</span>\n"
              f"-----------------------------------\n"
              f"Trabajo Final Fundamentos de Programacion\n"
              f"Grupo 3\n"
              f"Salon: 803\n"
              f"Carrera: Ingenieria de Redes y Comunicaciones\n"
              f"Universidad Peruana de Ciencias Aplicadas\n"
              f"<span style='color:black; font-weight:bold'>Exigete, Innova, UPC</span>")
    
    print(f" >> [ENVIANDO] Generando reporte ARP con firma...")
    
    # Envío del Correo:
    # Llamamos a nuestra función de correo "enviar_email", 
    # Si devuelve True, imprimimos éxito.
    if enviar_email(f"[ALERTA URGENTE] ARP Spoofing - {ip}", cuerpo, NOMBRE_LOGO):
        print(f" >> [EXITO] Alerta ARP enviada correctamente.")

def analizar_paquete_arp(pkt):
    """
    Funcion de Seguridad. Se ejecuta automáticamente CADA VEZ que pasa un paquete.
    """
    global ultima_alerta_arp    # Usamos la variable global para recordar cuándo fue la ultima alerta
    # pkt.haslayer(ARP): Filtra dentro de todos los paquetes que se reciben por segundo y solo se queda con los paquetes ARP
    # pkt[ARP].op == 2: los paquetes de tipo ARP que nos interesan son el tipo "2" (respuestas) ya que el tipo "1" es de (preguntas) y los atacantes siempre responden a preguntas haciendose pasar por otra mac
    if pkt.haslayer(ARP) and pkt[ARP].op == 2: 
        ip_src = pkt[ARP].psrc      # IP de quien envió el paquete 
        mac_src = pkt[ARP].hwsrc    # MAC física de quien envió el paquete
        # Verificación en Lista Blanca:
        if ip_src in IP_MAC_CONFIANZA:
            mac_real = IP_MAC_CONFIANZA[ip_src]
            if mac_src != mac_real:
                # Control de Spam (Cooldown):
                ahora = time.time()
                if (ahora - ultima_alerta_arp) > TIEMPO_ENTRE_ALERTAS: # ¿Han pasado más de 10 segundos desde el último aviso?
                    aviso = f"\n{ROJO}[!!!] ATAQUE ARP: IP {ip_src} suplantada por {mac_src}{RESET}"
                    print(aviso)
                    logging.warning(aviso)  # Guardamos la evidencia en el log
                    # Llamada única a la función de alerta
                    enviar_alerta_arp(ip_src, mac_src, mac_real)
                    ultima_alerta_arp = ahora   # Reiniciamos el reloj para esperar otros 10 segundos antes de molestar de nuevo

def ejecutar_arp_sniffer():
    """
    Funcion que arranca la vigilancia "Sniffer"
    """
    print("=================================================")
    print(f"{AMARILLO}[*] MONITOR ARP ACTIVADO (Ctrl + C para salir){RESET}")
    print(f"[*] Mi IP Local: {obtener_ip_local()}")
    print("=================================================")
    try:
        # sniff() es la función de la librería Scapy.
        # iface: Qué tarjeta de red usar
        # filter: Solo escuchar paquetes ARP (ignora el resto para ahorrar CPU)
        # prn: "Per Packet Runtime" -> Qué función ejecutar por cada paquete
        # store=0: NO guardar paquetes en memoria RAM (evita que la PC se ponga lenta)
        sniff(iface=NOMBRE_INTERFAZ, filter="arp", prn=analizar_paquete_arp, store=0)
    except KeyboardInterrupt:
        # Si el usuario presiona Ctrl+C detenemos el Sniffer y regresamos al menu de modulos.
        print(f"\n{VERDE}[*] Deteniendo ARP...{RESET}")
        time.sleep(1)

# ==============================================================================
# 5. MÓDULO ANCHO DE BANDA
# ==============================================================================
def generar_grafico_trafico():
    """
    Función que lee el historial (CSV) y crea una imagen PNG (Gráfico).
    """
    print(f"[*] Generando gráfico optimizado...")
    try:
        df = pd.read_csv(ARCHIVO_CSV)   # Usamos Pandas para abrir el 'Excel' (CSV) de forma super rápida
        if df.empty: return     # Si el archivo está vacío (no hubo datos), cancelamos para no causar error

        # Los datos vienen en 'Bytes' números grandes y dificiles de leer
        # Dividimos entre 1024*1024 para convertirlos a MegaBytes (MB), que son más legibles 
        df['Bajada_MB'] = df['Bytes_Bajada'] / (1024 * 1024)
        df['Subida_MB'] = df['Bytes_Subida'] / (1024 * 1024)
        
        plt.figure(figsize=(12, 6))   # Definimos el tamaño de la imagen (12 pulgadas de ancho x 6 de alto)

        # Dibujamos las líneas: Verde para descargas, Azul punteada para subidas
        plt.plot(df.index, df['Bajada_MB'], label='Bajada (MB/s)', color='green')
        plt.plot(df.index, df['Subida_MB'], label='Subida (MB/s)', color='blue', linestyle='--')
        
        # Limpieza del eje X
        total = len(df)     # Si mostramos TODAS las horas, se solapan y no se leen
        if total > 10:
            # Si hay muchos datos, mostramos solo 1 de cada 10 etiquetas
            salto = total // 10
            idxs = range(0, total, salto)
            plt.xticks(idxs, df['Tiempo'].iloc[idxs], rotation=45)
        else:
            # Si son pocos datos, mostramos todos.
            plt.xticks(range(total), df['Tiempo'], rotation=45)

        # Ponemos título, leyenda y guardamos la foto en el disco duro.
        plt.title('Consumo de Ancho de Banda')
        plt.legend(); plt.grid(True); plt.tight_layout()
        plt.savefig(ARCHIVO_IMG); plt.close()
        print(f"[*] Gráfico guardado: {ARCHIVO_IMG}")
    except Exception as e: print(f"[!] Error gráfico: {e}")

def monitor_ancho_banda():
    """
    Función principal que mide la velocidad segundo a segundo.
    """
    global ultima_alerta_bw     # Variable para recordar cuándo enviamos el último correo
    mi_ip = obtener_ip_local()
    # Presentación visual en consola
    print("=================================================")
    print(f"{AMARILLO}[*] MONITOR DE ANCHO DE BANDA ACTIVADO (Ctrl + C para salir){RESET}")
    print(f"[*] Alerta > {UMBRAL_MBPS} Mbps")
    print(f"[*] IP Monitor: {mi_ip}")
    print("=================================================")

    # Preparamos el archivo CSV (Borrador nuevo):
    # 'w' significa Write (Sobrescribir). Borra el historial anterior y empieza uno nuevo
    with open(ARCHIVO_CSV, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Tiempo", "Bytes_Bajada", "Bytes_Subida"])

    # TOMA 1: Leemos el contador de la tarjeta de red AHORA
    contadores_antiguos = psutil.net_io_counters(pernic=True)

    try:
        while True:
            # Pausa de 1 segundo exacto
            time.sleep(1)
            # Leemos el contador de nuevo tras 1 segundo
            contadores_nuevos = psutil.net_io_counters(pernic=True)
            # Verificamos si tu tarjeta existe
            if NOMBRE_INTERFAZ in contadores_nuevos:

                # CÁLCULO MATEMÁTICO (La Resta):
                datos_nuevos = contadores_nuevos[NOMBRE_INTERFAZ]
                datos_antiguos = contadores_antiguos[NOMBRE_INTERFAZ]

                # Lo que hay ahora MENOS lo que había hace 1 segundo = Lo que pasó por el cable
                b_recv = datos_nuevos.bytes_recv - datos_antiguos.bytes_recv
                b_sent = datos_nuevos.bytes_sent - datos_antiguos.bytes_sent

                # Conversión a Megabits (Mbps) para saber la velocidad de internet
                mbps_bajada = (b_recv * 8) / 1_000_000
                mbps_subida = (b_sent * 8) / 1_000_000
                total_mbps = mbps_bajada + mbps_subida
                hora = datetime.datetime.now().strftime("%H:%M:%S") # Obtenemos la hora actual para el reporte

                # Colores Dinámicos:
                # Si la velocidad supera el límite, píntalo ROJO, si no, VERDE/AZUL.
                col_b = ROJO if mbps_bajada > UMBRAL_MBPS else VERDE
                col_s = ROJO if mbps_subida > UMBRAL_MBPS else AZUL
                
                # Imprimir en pantalla el estado actual
                print(f"[{hora}] Bajada: {col_b}{convertir_bytes(b_recv)}/s{RESET} | Subida: {col_s}{convertir_bytes(b_sent)}/s{RESET}")

                # --- SISTEMA DE ALERTA ---
                if total_mbps > UMBRAL_MBPS:
                    ahora = time.time()
                    if (ahora - ultima_alerta_bw) > TIEMPO_ENTRE_ALERTAS_BW:
                        print(f" {ROJO}[!] ALERTA ENVIADA AL CORREO{RESET}")
                        logging.warning(f"ALERTA TRÁFICO: {total_mbps:.2f} Mbps")
                        
                        # Usamos etiquetas HTML simples mezcladas con el texto
                        cuerpo = (f"<strong>ALERTA DE ANCHO DE BANDA CRÍTICO</strong>\n\n"
                                  f"Reportado por el equipo: {mi_ip}\n"
                                  f"Hora del evento: {hora}\n"
                                  f"-----------------------------------\n"
                                  f"Velocidad Total: <span style='color:red; font-weight:bold'>{total_mbps:.2f} Mbps</span>\n"
                                  f"Descarga: {mbps_bajada:.2f} Mbps\n"
                                  f"Subida: {mbps_subida:.2f} Mbps\n"
                                  f"-----------------------------------\n"
                                  f"Trabajo Final Fundamentos de Programacion\n"
                                  f"Grupo 3\n"
                                  f"Salon: 803\n"
                                  f"Carrera: Ingenieria de Redes y Comunicaciones\n"
                                  f"Universidad Peruana de Ciencias Aplicadas\n"
                                  f"<strong>Exigete, Innova, UPC</strong>")
                        
                        # Llamamos a la función que pone el logo al final
                        enviar_email(f"[ALERTA TRÁFICO] {total_mbps:.0f} Mbps Detectados", cuerpo, NOMBRE_LOGO)
                        
                        ultima_alerta_bw = ahora    # Reseteamos el reloj

                # Guardamos los datos en el cuaderno (CSV) para el gráfico final
                with open(ARCHIVO_CSV, mode='a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow([hora, b_recv, b_sent])
                contadores_antiguos = contadores_nuevos # Actualizamos la referencia para el siguiente segundo
            else:
                print(f"Error: Interfaz {NOMBRE_INTERFAZ} no encontrada."); break
            
    # Si presionas Ctrl + C, salimos del bucle y preguntamos si quieres que se exporte el Grafico.                      
    except KeyboardInterrupt:
        print("\n[*] Deteniendo monitor...")
        if input("¿Generar gráfico? (s/n): ").lower() == 's': generar_grafico_trafico()
# ==============================================================================
# 6. FUNCIÓN PRINCIPAL
# ==============================================================================
def main():
    """
    Función principal que orquesta el flujo del programa.
    Mantiene al usuario en un bucle hasta que seleccione la opcion salir.
    """
    # Mostramos el logo y la presentacion UNA sola vez al inicio
    crear_caratula(NOMBRE_LOGO, ancho_logo=30)
    
    # El programa se congela aquí. No hace nada hasta que el usuario presiona Enter
    input(f"{AMARILLO}>> Presiona ENTER para iniciar...{RESET}")
    
    # El Menú de opciones:
    while True:
        limpiar_pantalla()
        mostrar_menu()
        op = input("Opción: ")
        
        if op == "1": 
            ejecutar_arp_sniffer()
            
        elif op == "2": 
            monitor_ancho_banda()
            
        elif op == "3":
            try:
                with open('seguridad_sistema.log', 'r') as f: print(f.read())
            except: print("Sin logs.")
            input("Enter para volver.")
            
        elif op == "4": 
            print(f"\n{AMARILLO}Cerrando sistema... ¡Hasta luego!{RESET}")
            time.sleep(1) # Le damos un segundo para leer la despedida
            break
            
        else: 
            # Si el usuario escribe "5", "hola" o da Enter vacío:
            print(f"\n{ROJO}[!] ERROR: La opción '{op}' no es válida.{RESET}")
            print(f"{ROJO}Por favor, seleccione un número del 1 al 4.{RESET}")
            
            # Pausa obligatoria para que el usuario lea el error antes de limpiar pantalla
            input(f"\nPresiona {NEGRITA}ENTER{RESET} para intentar nuevamente...")

if __name__ == "__main__": 
    main()
    
