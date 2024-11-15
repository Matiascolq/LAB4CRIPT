from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
import base64

# Punto 2.2: Solicitar datos al usuario
def solicitar_datos():
    print("Seleccione el algoritmo de cifrado:")
    print("1. DES")
    print("2. 3DES")
    print("3. AES-256")
    opcion = input("Ingrese el número correspondiente al algoritmo: ")

    if opcion == '1':
        algoritmo = 'DES'
        longitud_clave = 8
        longitud_iv = 8
    elif opcion == '2':
        algoritmo = '3DES'
        longitud_clave = 24
        longitud_iv = 8
    elif opcion == '3':
        algoritmo = 'AES-256'
        longitud_clave = 32
        longitud_iv = 16
    else:
        print("Opción no válida. Por favor, seleccione 1, 2 o 3.")
        exit()

    clave_usuario = input(f"Ingrese la clave de cifrado (mínimo {longitud_clave} caracteres): ")
    iv_usuario = input(f"Ingrese el vector de inicialización (mínimo {longitud_iv} caracteres): ")

    if len(clave_usuario) < longitud_clave:
        clave_usuario = clave_usuario.ljust(longitud_clave, 'X')  # Completar con 'X'
    elif len(clave_usuario) > longitud_clave:
        clave_usuario = clave_usuario[:longitud_clave]  # Truncar

    if len(iv_usuario) < longitud_iv:
        iv_usuario = iv_usuario.ljust(longitud_iv, 'X')  # Completar con 'X'
    elif len(iv_usuario) > longitud_iv:
        iv_usuario = iv_usuario[:longitud_iv]  # Truncar

    return algoritmo, clave_usuario, iv_usuario

# Punto 2.3: Ajustar la clave y el IV según el algoritmo seleccionado
def ajustar_clave_iv(clave_usuario, iv_usuario, longitud_clave, longitud_iv):
    # Ajustar la clave
    if len(clave_usuario) < longitud_clave:
        clave_ajustada = clave_usuario.ljust(longitud_clave, 'X')
    else:
        clave_ajustada = clave_usuario[:longitud_clave]

    # Ajustar el IV
    if len(iv_usuario) < longitud_iv:
        iv_ajustado = iv_usuario.ljust(longitud_iv, 'X')
    else:
        iv_ajustado = iv_usuario[:longitud_iv]

    return clave_ajustada.encode('utf-8'), iv_ajustado.encode('utf-8')

# Punto 2.4: Implementar el cifrado y descifrado en modo CBC
def cifrar_descifrar(algoritmo, clave, iv):
    texto_plano = input("Ingrese el texto a cifrar: ").encode('utf-8')

    if algoritmo == 'DES':
        cipher = DES.new(clave, DES.MODE_CBC, iv)
    elif algoritmo == '3DES':
        try:
            cipher = DES3.new(clave, DES3.MODE_CBC, iv)
        except ValueError:
            print("Error: Clave no válida para 3DES. Por favor, revise los requisitos.")
            exit()
    elif algoritmo == 'AES-256':
        cipher = AES.new(clave, AES.MODE_CBC, iv)

    # Cifrado
    texto_cifrado = cipher.encrypt(pad(texto_plano, cipher.block_size))
    texto_cifrado_b64 = base64.b64encode(texto_cifrado).decode('utf-8')
    print(f"Texto cifrado (Base64): {texto_cifrado_b64}")

    # Descifrado
    texto_cifrado = base64.b64decode(texto_cifrado_b64)
    if algoritmo == 'DES':
        cipher = DES.new(clave, DES.MODE_CBC, iv)
    elif algoritmo == '3DES':
        cipher = DES3.new(clave, DES3.MODE_CBC, iv)
    elif algoritmo == 'AES-256':
        cipher = AES.new(clave, AES.MODE_CBC, iv)

    texto_descifrado = unpad(cipher.decrypt(texto_cifrado), cipher.block_size)
    print(f"Texto descifrado: {texto_descifrado.decode('utf-8')}")

if __name__ == "__main__":
    algoritmo, clave_usuario, iv_usuario = solicitar_datos()
    clave, iv = ajustar_clave_iv(clave_usuario, iv_usuario, len(clave_usuario), len(iv_usuario))
    cifrar_descifrar(algoritmo, clave, iv)
