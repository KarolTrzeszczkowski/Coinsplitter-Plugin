from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
import webbrowser
from .split_contract import SplitContract
from electroncash.address import Address, Script, hash160, ScriptOutput
from electroncash.transaction import Transaction,TYPE_ADDRESS
import electroncash.web as web

from electroncash.i18n import _
from electroncash_gui.qt.util import *
from electroncash.wallet import Multisig_Wallet
from electroncash.util import print_error, print_stderr, NotEnoughFunds
from electroncash_gui.qt.transaction_dialog import show_transaction

class Ui(QDialog, MessageBoxMixin):
    search_done_signal = pyqtSignal(object)

    def __init__(self, parent, plugin, wallet_name, address):
        QDialog.__init__(self, parent)
        self.main_window = parent
        self.wallet=parent.wallet
        self.plugin = plugin
        self.wallet_name = wallet_name
        self.config = parent.config
        self.password=None
        if self.wallet.has_password():
            self.main_window.show_error(_("Coinsplitter Plugin requires password. It will get access to your private keys."))
            self.password = parent.password_dialog()
            if not self.password:
                return

        if address:
            self.fund_domain = [address]
            self.fund_change_address = address
            self.default_redeem_address = address
            self.entropy_address = address
        else:
            self.fund_domain = None
            self.fund_change_address = None
            self.default_redeem_address = self.wallet.get_unused_address()
            self.entropy_address = self.wallet.get_addresses()[0]
        if not self.default_redeem_address:
            # self.wallet.get_unused_address() returns None for imported privkey wallets.
            self.main_window.show_error(_("For imported private key wallets, please open the coin splitter from the Addresses tab by right clicking on an address, instead of via the Tools menu."))
            return

        # Extract private key
        index = self.wallet.get_address_index(self.entropy_address)

        key = self.wallet.keystore.get_private_key(index,self.password)
        privkey = int.from_bytes(key[0], 'big')

        if isinstance(self.wallet, Multisig_Wallet):
            self.main_window.show_error(
                "Multi-sig wallet support is partial.\nThe splitter coin itself is *not* multisig and belongs to you alone (it cannot be redeemed by other parties).")
        self.contract = SplitContract(privkey)

        self.setWindowTitle(_("OP_CHECKDATASIG Coin Splitting"))

        vbox = QVBoxLayout()
        self.setLayout(vbox)
        l = QLabel(_("Master address") + ": " + self.entropy_address.to_ui_string())
        l.setTextInteractionFlags(Qt.TextSelectableByMouse)
        vbox.addWidget(l)

        l = QLabel(_("Split contract") + ": " + self.contract.address.to_ui_string())
        l.setTextInteractionFlags(Qt.TextSelectableByMouse)
        vbox.addWidget(l)

        hbox = QHBoxLayout()
        vbox.addLayout(hbox)

        addr_URL = web.BE_URL(self.config, 'addr', self.contract.address)
        b = QPushButton(_("View on block explorer"))
        b.clicked.connect(lambda: webbrowser.open(addr_URL))
        hbox.addWidget(b)
        if not addr_URL:
            b.setDisabled(True)

        b = QPushButton(_("View redeem script..."))
        b.clicked.connect(self.showscript)
        hbox.addWidget(b)

        hbox.addStretch(1)


        l = QLabel("<b>%s</b>"%(_("Splittable coin creation/finding:")))
        vbox.addWidget(l)

        hbox = QHBoxLayout()
        vbox.addLayout(hbox)

        b = QPushButton(_("Create splittable coin"))
        b.clicked.connect(self.fund)
        hbox.addWidget(b)
        self.fund_button = b

        b = QPushButton("x")
        b.clicked.connect(self.search)
        hbox.addWidget(b)
        self.search_button = b

        hbox.addStretch(1)


        grid = QGridLayout()
        vbox.addLayout(grid)

        l = QLabel(_("TXID"))
        grid.addWidget(l, 0, 0)

        l = QLabel(_("Out#"))
        grid.addWidget(l, 0, 1)

        l = QLabel(_("Value (sats)"))
        grid.addWidget(l, 0, 2)

        self.fund_txid_e = QLineEdit()
        self.fund_txid_e.textEdited.connect(self.changed_coin)
        grid.addWidget(self.fund_txid_e, 1, 0)

        self.fund_txout_e = QLineEdit()
        self.fund_txout_e.setMaximumWidth(40)
        self.fund_txout_e.setAlignment(Qt.AlignRight)
        self.fund_txout_e.textEdited.connect(self.changed_coin)
        grid.addWidget(self.fund_txout_e, 1, 1)

        self.fund_value_e = QLineEdit()
        self.fund_value_e.setMaximumWidth(70)
        self.fund_value_e.setAlignment(Qt.AlignRight)
        self.fund_value_e.textEdited.connect(self.changed_coin)
        grid.addWidget(self.fund_value_e, 1, 2)


        l = QLabel("<b>%s</b>"%(_("Splittable coin spending:")))
        vbox.addWidget(l)

        self.option1_rb = QRadioButton(_("Only spend splittable coin"))
        self.option2_rb = QRadioButton()
        self.option3_rb = QRadioButton(_("Combine with all coins from wallet") + ' "%s"'%(self.wallet.basename()))
        vbox.addWidget(self.option1_rb)
        vbox.addWidget(self.option2_rb)
        vbox.addWidget(self.option3_rb)
        if self.fund_change_address:
            self.option2_rb.setText(_("Combine with all coins from address") + " %.10s..."%(self.fund_change_address.to_ui_string()))
            self.option2_rb.setChecked(True)
        else:
            self.option3_rb.setChecked(True)
            self.option2_rb.setHidden(True)


        hbox = QHBoxLayout()
        vbox.addLayout(hbox)
        l = QLabel(_("Output to:"))
        hbox.addWidget(l)
        self.redeem_address_e = QLineEdit()
        self.redeem_address_e.setText(self.default_redeem_address.to_full_ui_string())
        hbox.addWidget(self.redeem_address_e)


        hbox = QHBoxLayout()
        vbox.addLayout(hbox)

        b = QPushButton(_("Redeem with split (CDS chain only)"))
        b.clicked.connect(lambda: self.spend('redeem'))
        hbox.addWidget(b)
        self.redeem_button = b

        b = QPushButton(_("Refund (any chain)"))
        b.clicked.connect(lambda: self.spend('refund'))
        hbox.addWidget(b)
        self.refund_button = b

        self.changed_coin()

        self.search_done_signal.connect(self.search_done)
        self.search()

        self.show()

    def showscript(self, ):
        if not self.contract:
            return
        script = self.contract.redeemscript
        schex = script.hex()

        try:
            sco = ScriptOutput(script)
            decompiled = sco.to_ui_string()
        except:
            decompiled = "decompiling error"

        d = QDialog(self)
        d.setWindowTitle(_('Split contract script'))
        d.setMinimumSize(610, 490)

        layout = QGridLayout(d)

        script_bytes_e = QTextEdit()
        layout.addWidget(QLabel(_('Bytes')), 1, 0)
        layout.addWidget(script_bytes_e, 1, 1)
        script_bytes_e.setText(schex)
        script_bytes_e.setReadOnly(True)
        # layout.setRowStretch(2,3)

        decompiled_e = QTextEdit()
        layout.addWidget(QLabel(_('ASM')), 3, 0)
        layout.addWidget(decompiled_e, 3, 1)
        decompiled_e.setText(decompiled)
        decompiled_e.setReadOnly(True)
        # layout.setRowStretch(3,1)

        hbox = QHBoxLayout()

        b = QPushButton(_("Close"))
        b.clicked.connect(d.accept)
        hbox.addWidget(b)

        layout.addLayout(hbox, 4, 1)
        #        d.setWindowModality(Qt.WindowModal)
        #        d.exec_()
        d.show()

    def changed_coin(self, ):
        # if any of the txid/out#/value changes
        try:
            txid = bytes.fromhex(self.fund_txid_e.text())
            assert len(txid) == 32
            prevout_n = int(self.fund_txout_e.text())
            value = int(self.fund_value_e.text())
        except:
            self.redeem_button.setDisabled(True)
            self.refund_button.setDisabled(True)
        else:
            self.redeem_button.setDisabled(False)
            self.refund_button.setDisabled(False)

    def fund(self, ):
        outputs = [(TYPE_ADDRESS, self.contract.address, 1000)]
        try:
            tx = self.wallet.mktx(outputs, self.password, self.config,
                                  domain=self.fund_domain, change_addr=self.fund_change_address)
        except NotEnoughFunds:
            return self.show_critical(_("Not enough balance to fund smart contract."))
        except Exception as e:
            return self.show_critical(repr(e))
        for i, out in enumerate(tx.outputs()):
            if out[1] == self.contract.address:
                self.fund_txout_e.setText(str(i))
                self.fund_value_e.setText(str(out[2]))
                break
        else:
            raise RuntimeError("Created tx is incorrect!")
        self.fund_txid_e.setText(tx.txid())
        self.fund_txid_e.setCursorPosition(0)
        show_transaction(tx, self.main_window,
                         "Make splittable coin (master:%s)" % (self.entropy_address.to_ui_string()),
                         prompt_if_unsaved=True)
        self.changed_coin()

    def spend(self, mode):
        prevout_hash = self.fund_txid_e.text()
        prevout_n = int(self.fund_txout_e.text())
        value = int(self.fund_value_e.text())
        locktime = 0
        estimate_fee = lambda x: (1 * x)
        out_addr = Address.from_string(self.redeem_address_e.text())

        # generate the special spend
        inp = self.contract.makeinput(prevout_hash, prevout_n, value, mode)

        inputs = [inp]
        invalue = value

        # add on other spends
        if self.option1_rb.isChecked():
            domain = []
        elif self.option2_rb.isChecked():
            domain = [self.fund_change_address]
        elif self.option3_rb.isChecked():
            domain = None
        else:
            raise RuntimeError
        other_coins = self.wallet.get_utxos(domain, exclude_frozen=True, mature=True, confirmed_only=False)
        for coin in other_coins:
            self.wallet.add_input_info(coin)
            inputs.append(coin)
            invalue += coin['value']

        outputs = [(TYPE_ADDRESS, out_addr, 0)]
        tx1 = Transaction.from_io(inputs, outputs, locktime)
        txsize = len(tx1.serialize(True)) // 2
        fee = estimate_fee(txsize)

        outputs = [(TYPE_ADDRESS, out_addr, invalue - fee)]
        tx = Transaction.from_io(inputs, outputs, locktime)
        self.contract.signtx(tx)
        self.wallet.sign_transaction(tx, self.password)
        self.contract.completetx(tx)

        if mode == 'refund':
            desc = "Spend splittable coin (replayable on any chain)"
        elif mode == 'redeem':
            desc = "Spend splittable coin (CDS chain only!)"
        show_transaction(tx, self.main_window,
                         desc,
                         prompt_if_unsaved=True)

    def search(self, ):
        self.search_button.setIcon(QIcon(":icons/status_waiting"))
        self.search_button.setText(_("Searching..."))
        self.search_button.setDisabled(True)

        self.wallet.network.send([("blockchain.scripthash.listunspent",
                                   [self.contract.address.to_scripthash_hex()]),
                                  ],
                                 self.search_done_signal.emit)

    def search_done(self, response):
        error = response.get('error')
        result = response.get('result')
        params = response.get('params')

        if result and not error:
            # just grab first utxo
            utxo = result[0]
            self.fund_txid_e.setText(utxo['tx_hash'])
            self.fund_txid_e.setCursorPosition(0)
            self.fund_txout_e.setText(str(utxo['tx_pos']))
            self.fund_value_e.setText(str(utxo['value']))
            self.changed_coin()
            self.search_button.setIcon(QIcon(":icons/tab_coins"))
            self.search_button.setText(_("Found splittable coin!"))
            self.search_button.setDisabled(True)
            self.fund_button.setDisabled(True)
            return

        if error:
            self.show_error("Search request error: " + str(error))

        self.search_button.setIcon(QIcon())
        self.search_button.setText(_("Find splittable coin"))
        self.search_button.setDisabled(False)
    def create_menu(self):
        pass

    def on_delete(self):
        pass

    def on_update(self):
        pass