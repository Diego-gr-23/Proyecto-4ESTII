from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTabWidget, QTextEdit, QPushButton,
    QFileDialog, QMessageBox, QLabel, QHBoxLayout, QLineEdit
)
from PyQt6.QtCore import Qt
from crypto_core import RSAKeyManager, HybridCipher, DigitalSignature, FNV1aHash
from crypto_nodes import KeyPair, MessageNode

class CryptoApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Proyecto 4 - Encripción Asimétrica y Firma Digital")
        self.resize(900, 600)

        self.keys = KeyPair()

        layout = QVBoxLayout()
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Tabs
        self.tabs.addTab(self.tab_keys(), "Claves")
        self.tabs.addTab(self.tab_crypto(), "Cifrado / Descifrado")
        self.tabs.addTab(self.tab_sign(), "✍Firma / Verificación")
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

        btn_enc = QPushButton("Cifrar mensaje")
        btn_enc.clicked.connect(self.encrypt)
        btn_dec = QPushButton("Descifrar mensaje")
        btn_dec.clicked.connect(self.decrypt)

        for widget in [
            QLabel("Mensaje claro:"), self.txt_plain, btn_enc,
            QLabel("Texto cifrado:"), self.txt_cipher, btn_dec,
            QLabel("Resultado descifrado:"), self.txt_result
        ]:
            v.addWidget(widget)
        w.setLayout(v)
        return w

    def encrypt(self):
        if not self.keys.public_key:
            QMessageBox.warning(self, "Advertencia", "Primero carga la clave pública.")
            return
        msg = self.txt_plain.toPlainText().encode()
        node = MessageNode(msg)
        package = HybridCipher.encrypt(node, self.keys.public_key)
        self.txt_cipher.setPlainText(package.decode())
        QMessageBox.information(self, "Éxito", "Mensaje cifrado correctamente.")

    def decrypt(self):
        if not self.keys.private_key:
            QMessageBox.warning(self, "Advertencia", "Primero carga la clave privada.")
            return
        try:
            data = self.txt_cipher.toPlainText().encode()
            msg = HybridCipher.decrypt(data, self.keys.private_key)
            self.txt_result.setPlainText(msg.content.decode(errors="ignore"))
            QMessageBox.information(self, "Éxito", "Descifrado correctamente.")
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

        btn_sign = QPushButton("Firmar")
        btn_sign.clicked.connect(self.sign)
        btn_verify = QPushButton("Verificar firma")
        btn_verify.clicked.connect(self.verify)

        for widget in [
            QLabel("Mensaje a firmar:"), self.txt_sign_input,
            btn_sign, QLabel("Firma (base64):"), self.txt_sign_output,
            QLabel("Hash FNV-1a:"), self.hash_label, btn_verify
        ]:
            v.addWidget(widget)
        w.setLayout(v)
        return w

    def sign(self):
        if not self.keys.private_key:
            QMessageBox.warning(self, "Advertencia", "Primero carga la clave privada.")
            return
        data = self.txt_sign_input.toPlainText().encode()
        sig_node = DigitalSignature.sign(data, self.keys.private_key)
        self.txt_sign_output.setPlainText(sig_node.signature.hex())
        self.hash_label.setText(FNV1aHash.compute(data))
        QMessageBox.information(self, "Firmado", "Firma generada correctamente.")

    def verify(self):
        if not self.keys.public_key:
            QMessageBox.warning(self, "Advertencia", "Primero carga la clave pública.")
            return
        try:
            data = self.txt_sign_input.toPlainText().encode()
            sig = bytes.fromhex(self.txt_sign_output.toPlainText().strip())
            ok = DigitalSignature.verify(data, sig, self.keys.public_key)
            QMessageBox.information(self, "Resultado", "Firma válida" if ok else "Firma inválida")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
