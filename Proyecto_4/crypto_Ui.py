from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTabWidget, QTextEdit, QPushButton,
    QFileDialog, QMessageBox, QLabel, QHBoxLayout, QLineEdit
)
from PyQt6.QtCore import Qt
from crypto_core import RSAKeyManager, HybridCipher, DigitalSignature, FNV1aHash
from crypto_nodes import KeyPair, MessageNode
import os

class CryptoApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Proyecto 4 - Encripción Asimétrica y Firma Digital")
        self.resize(900, 600)

        # --- 🔹 Estilo CSS aplicado a toda la app ---
        self.setStyleSheet("""
                    QWidget {
                        background-color: #f5f7fa;
                        font-family: Segoe UI;
                        font-size: 14px;
                    }
                    QPushButton {
                        background-color: #0078d4;
                        color: white;
                        border-radius: 6px;
                        padding: 6px 10px;
                    }
                    QPushButton:hover {
                        background-color: #005fa3;
                    }
                    QTextEdit, QLineEdit {
                        background-color: white;
                        border: 1px solid #ccc;
                        border-radius: 6px;
                        padding: 4px;
                    }
                    QLabel {
                        font-weight: bold;
                        color: #333;
                    }
                    QTabWidget::pane {
                        border: 2px solid #0078d4;
                        border-radius: 8px;
                        margin-top: -1px;
                        background-color: white;
                    }
                    QTabBar::tab {
                        background: #d9e5f3;
                        border: 1px solid #0078d4;
                        color: #333;
                        border-top-left-radius: 6px;
                        border-top-right-radius: 6px;
                        padding: 8px 18px;
                        margin-right: 4px;
                    }
                    QTabBar::tab:selected {
                        background: #0078d4;
                        color: white;
                        font-weight: bold;
                    }
                    QTabBar::tab:hover {
                        background: #4097e1;
                        color: white;
                    }
                """)

        self.keys = KeyPair()
        self.current_file_node = None
        self.current_sign_file_node = None

        layout = QVBoxLayout()
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        self.tabs.addTab(self.tab_keys(), "Claves")
        self.tabs.addTab(self.tab_crypto(), "Cifrado / Descifrado")
        self.tabs.addTab(self.tab_sign(), "Firma / Verificación")

        self.setLayout(layout)

    # --- Tab 1 ---
    def tab_keys(self):
        w = QWidget()
        v = QVBoxLayout()

        info = QTextEdit()
        info.setReadOnly(True)

        btn_gen = QPushButton("Generar par RSA")
        btn_gen.clicked.connect(lambda: self.generate_keys(info))
        btn_save_priv = QPushButton("Guardar clave privada")
        btn_save_priv.clicked.connect(lambda: self.save_priv(info))
        btn_save_pub = QPushButton("Guardar clave pública")
        btn_save_pub.clicked.connect(lambda: self.save_pub(info))
        btn_load_priv = QPushButton("Cargar clave privada")
        btn_load_priv.clicked.connect(lambda: self.load_priv(info))
        btn_load_pub = QPushButton("Cargar clave pública")
        btn_load_pub.clicked.connect(lambda: self.load_pub(info))

        for b in [btn_gen, btn_save_priv, btn_save_pub, btn_load_priv, btn_load_pub]:
            v.addWidget(b)
        v.addWidget(info)

        w.setLayout(v)
        return w

    def generate_keys(self, info):
        self.keys = RSAKeyManager.generate()
        info.setPlainText("Claves generadas correctamente (RSA 2048).")

    def save_priv(self, info):
        if not self.keys.private_key:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Guardar clave privada", filter="*.pem")
        if path:
            RSAKeyManager.save_private(self.keys.private_key, path)
            QMessageBox.information(self, "OK", "Clave privada guardada.")

    def save_pub(self, info):
        if not self.keys.public_key:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Guardar clave pública", filter="*.pem")
        if path:
            RSAKeyManager.save_public(self.keys.public_key, path)
            QMessageBox.information(self, "OK", "Clave pública guardada.")

    def load_priv(self, info):
        path, _ = QFileDialog.getOpenFileName(self, "Cargar clave privada", filter="*.pem")
        if path:
            self.keys = RSAKeyManager.load_private(path)
            info.setPlainText("Clave privada cargada y clave pública derivada.")

    def load_pub(self, info):
        path, _ = QFileDialog.getOpenFileName(self, "Cargar clave pública", filter="*.pem")
        if path:
            self.keys.public_key = RSAKeyManager.load_public(path)
            info.setPlainText("Clave pública cargada correctamente.")

    # --- Tab 2 ---
    def tab_crypto(self):
        w = QWidget()
        v = QVBoxLayout()

        self.txt_plain = QTextEdit()
        self.txt_cipher = QTextEdit()
        self.txt_result = QTextEdit()
        self.txt_result.setReadOnly(True)

        btn_select_file = QPushButton("Seleccionar archivo para cifrar")
        btn_select_file.clicked.connect(self.select_file_for_encryption)
        btn_enc = QPushButton("Cifrar mensaje / archivo")
        btn_enc.clicked.connect(self.encrypt)
        btn_save_package = QPushButton("Guardar paquete cifrado en archivo")
        btn_save_package.clicked.connect(self.save_encrypted_package)
        btn_load_package = QPushButton("Cargar paquete cifrado desde archivo")
        btn_load_package.clicked.connect(self.load_encrypted_package)
        btn_dec = QPushButton("Descifrar mensaje / paquete")
        btn_dec.clicked.connect(self.decrypt)

        for widget in [
            QLabel("Mensaje claro (o info de archivo):"), self.txt_plain,
            btn_select_file, btn_enc,
            QLabel("Texto cifrado (paquete JSON):"), self.txt_cipher,
            btn_save_package, btn_load_package, btn_dec,
            QLabel("Resultado descifrado:"), self.txt_result
        ]:
            v.addWidget(widget)

        w.setLayout(v)
        return w

    def select_file_for_encryption(self):
        path, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo", filter="Todos los archivos (*)")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
                filename = os.path.basename(path)
                self.current_file_node = MessageNode(data, filename)
                preview = f"Archivo seleccionado: {filename}\nTamaño: {len(data)} bytes\nRuta: {path}"
                try:
                    text_preview = data.decode(errors="strict")
                    if len(text_preview) > 1000:
                        text_preview = text_preview[:1000] + "\n... (previsualización truncada)"
                    preview += "\n\nPrevisualización:\n" + text_preview
                except Exception:
                    preview += "\n\n(Previsualización no disponible: contenido binario)"
                self.txt_plain.setPlainText(preview)
                QMessageBox.information(self, "Archivo cargado", f"Archivo '{filename}' cargado en memoria para cifrar.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo leer el archivo: {e}")

    def encrypt(self):
        if not self.keys.public_key:
            QMessageBox.warning(self, "Advertencia", "Primero carga la clave pública.")
            return
        try:
            if self.current_file_node:
                node = self.current_file_node
            else:
                msg = self.txt_plain.toPlainText().encode()
                node = MessageNode(msg, "mensaje.txt")
            package = HybridCipher.encrypt(node, self.keys.public_key)
            self.txt_cipher.setPlainText(package.decode())
            QMessageBox.information(self, "Éxito", "Mensaje/archivo cifrado correctamente.")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def save_encrypted_package(self):
        if not self.txt_cipher.toPlainText().strip():
            QMessageBox.warning(self, "Advertencia", "No hay paquete cifrado para guardar.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Guardar paquete cifrado", filter="Paquete (*.bin *.json);;Todos (*)")
        if not path:
            return
        try:
            data = self.txt_cipher.toPlainText().encode()
            with open(path, "wb") as f:
                f.write(data)
            QMessageBox.information(self, "Guardado", f"Paquete cifrado guardado en: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo guardar: {e}")

    def load_encrypted_package(self):
        path, _ = QFileDialog.getOpenFileName(self, "Abrir paquete cifrado", filter="Paquete (*.bin *.json);;Todos (*)")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
                try:
                    text = data.decode()
                except Exception:
                    text = data.decode(errors="ignore")
                self.txt_cipher.setPlainText(text)
                QMessageBox.information(self, "Cargado", "Paquete cifrado cargado en el cuadro de texto.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo abrir el paquete: {e}")

    def decrypt(self):
        if not self.keys.private_key:
            QMessageBox.warning(self, "Advertencia", "Primero carga la clave privada.")
            return
        try:
            data = self.txt_cipher.toPlainText().encode()
            msg_node = HybridCipher.decrypt(data, self.keys.private_key)
            try:
                text = msg_node.content.decode(errors="strict")
                self.txt_result.setPlainText(text)
                if msg_node.filename:
                    save = QMessageBox.question(self, "Guardar archivo",
                        f"El paquete contenía el archivo '{msg_node.filename}'. ¿Deseas guardarlo en disco?")
                    if save == QMessageBox.StandardButton.Yes:
                        path, _ = QFileDialog.getSaveFileName(self, "Guardar archivo descifrado",
                            default=msg_node.filename, filter="Todos los archivos (*)")
                        if path:
                            with open(path, "wb") as f:
                                f.write(msg_node.content)
                            QMessageBox.information(self, "Guardado", f"Archivo guardado en: {path}")
                    else:
                        QMessageBox.information(self, "Descifrado", "Descifrado correctamente (texto).")
            except Exception:
                self.txt_result.setPlainText("(Contenido binario no mostrado)")
                if msg_node.filename:
                    path, _ = QFileDialog.getSaveFileName(self, "Guardar archivo descifrado",
                        default=msg_node.filename, filter="Todos los archivos (*)")
                    if path:
                        with open(path, "wb") as f:
                            f.write(msg_node.content)
                        QMessageBox.information(self, "Guardado", f"Archivo guardado en: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # --- Tab 3 ---
    def tab_sign(self):
        w = QWidget()
        v = QVBoxLayout()

        self.txt_sign_input = QTextEdit()
        self.txt_sign_output = QTextEdit()
        self.txt_sign_output.setReadOnly(True)
        self.hash_label = QLineEdit()
        self.hash_label.setReadOnly(True)

        btn_select_sign_file = QPushButton("Seleccionar archivo para firmar")
        btn_select_sign_file.clicked.connect(self.select_file_for_signing)
        btn_sign = QPushButton("Firmar")
        btn_sign.clicked.connect(self.sign)
        btn_save_sig = QPushButton("Guardar firma en archivo")
        btn_save_sig.clicked.connect(self.save_signature_to_file)
        btn_load_sig = QPushButton("Cargar firma desde archivo (para verificar)")
        btn_load_sig.clicked.connect(self.load_signature_file_for_verification)
        btn_verify = QPushButton("Verificar firma")
        btn_verify.clicked.connect(self.verify)

        for widget in [
            QLabel("Mensaje a firmar (o info de archivo):"), self.txt_sign_input,
            btn_select_sign_file, btn_sign, btn_save_sig,
            QLabel("Firma (hex):"), self.txt_sign_output,
            QLabel("Hash FNV-1a:"), self.hash_label,
            btn_load_sig, btn_verify
        ]:
            v.addWidget(widget)

        w.setLayout(v)
        return w

    def select_file_for_signing(self):
        path, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo para firmar", filter="Todos los archivos (*)")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
                filename = os.path.basename(path)
                self.current_sign_file_node = MessageNode(data, filename)
                preview = f"Archivo seleccionado para firmar: {filename}\nTamaño: {len(data)} bytes\nRuta: {path}"
                try:
                    text_preview = data.decode(errors="strict")
                    if len(text_preview) > 1000:
                        text_preview = text_preview[:1000] + "\n... (previsualización truncada)"
                    preview += "\n\nPrevisualización:\n" + text_preview
                except Exception:
                    preview += "\n\n(Previsualización no disponible: contenido binario)"
                self.txt_sign_input.setPlainText(preview)
                QMessageBox.information(self, "Archivo cargado", f"Archivo '{filename}' cargado en memoria para firmar.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo leer el archivo: {e}")

    def sign(self):
        if not self.keys.private_key:
            QMessageBox.warning(self, "Advertencia", "Primero carga la clave privada.")
            return
        try:
            if self.current_sign_file_node:
                data = self.current_sign_file_node.content
            else:
                data = self.txt_sign_input.toPlainText().encode()
            sig_node = DigitalSignature.sign(data, self.keys.private_key)
            self.txt_sign_output.setPlainText(sig_node.signature.hex())
            self.hash_label.setText(FNV1aHash.compute(data))
            QMessageBox.information(self, "Firmado", "Firma generada correctamente.")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def save_signature_to_file(self):
        sig_hex = self.txt_sign_output.toPlainText().strip()
        if not sig_hex:
            QMessageBox.warning(self, "Advertencia", "No hay firma para guardar.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Guardar firma", filter="Firma (*.sig *.txt);;Todos (*)")
        if not path:
            return
        try:
            with open(path, "w") as f:
                f.write(sig_hex)
            QMessageBox.information(self, "Guardado", f"Firma guardada en: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo guardar la firma: {e}")

    def load_signature_file_for_verification(self):
        path, _ = QFileDialog.getOpenFileName(self, "Cargar firma", filter="Firma (*.sig *.txt);;Todos (*)")
        if not path:
            return
        try:
            with open(path, "r") as f:
                sig_text = f.read().strip()
                self.txt_sign_output.setPlainText(sig_text)
            QMessageBox.information(self, "Cargado", "Firma cargada en el cuadro de firma.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo leer la firma: {e}")

    def verify(self):
        if not self.keys.public_key:
            QMessageBox.warning(self, "Advertencia", "Primero carga la clave pública.")
            return
        try:
            if self.current_sign_file_node:
                data = self.current_sign_file_node.content
            else:
                data = self.txt_sign_input.toPlainText().encode()
            sig_hex = self.txt_sign_output.toPlainText().strip()
            sig = bytes.fromhex(sig_hex)
            ok = DigitalSignature.verify(data, sig, self.keys.public_key)
            QMessageBox.information(self, "Resultado", "Firma válida" if ok else "Firma inválida")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
