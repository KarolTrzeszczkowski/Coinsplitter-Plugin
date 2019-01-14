from ecdsa.ecdsa import curve_secp256k1, generator_secp256k1
from electroncash.bitcoin import ser_to_point, point_to_ser
from electroncash.address import Address, Script, hash160, ScriptOutput
import hashlib
from .op_codes import OpCodes


def joinbytes(iterable):
    """Joins an iterable of bytes and/or integers into a single byte string"""
    return b''.join((bytes((x,)) if isinstance(x,int) else x) for x in iterable)

class SplitContract:
    """Contract for making coins that can only be spent on BCH chains supporting
    OP_CHECKDATASIGVERIFY, with backup clause for recovering dust on non-supporting
    chains."""
    def __init__(self, master_privkey):
        G = generator_secp256k1
        order = G.order()

        # make two derived private keys (integers between 1 and p-1 inclusive)

        # hard derivation (irreversible):
        x = int.from_bytes(hashlib.sha512(b'Split1' + master_privkey.to_bytes(32, 'big')).digest(), 'big')
        self.priv1 = 1 + (x % (order-1))
        x = int.from_bytes(hashlib.sha512(b'Split2' + master_privkey.to_bytes(32, 'big')).digest(), 'big')
        self.priv2 = 1 + (x % (order-1))

        # soft derivation (reversible):
        #self.priv1 = (0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa * master_privkey) % order
        #self.priv2 = (0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb * master_privkey) % order

        # generate compressed pubkeys
        self.pub1ser = point_to_ser(self.priv1 * G, True)
        self.pub2ser = point_to_ser(self.priv2 * G, True)

        self.keypairs = {
            self.pub1ser.hex() : (self.priv1.to_bytes(32, 'big'), True),
            self.pub2ser.hex() : (self.priv2.to_bytes(32, 'big'), True),
            }

        # params from ABC 0.18.2 unit tests
        cds_sig = bytes.fromhex('30440220256c12175e809381f97637933ed6ab97737d263eaaebca6add21bced67fd12a402205ce29ecc1369d6fc1b51977ed38faaf41119e3be1d7edfafd7cfaf0b6061bd07')
        cds_msg = b''
        cds_pubkey = bytes.fromhex('038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508')
        self.redeemscript = joinbytes([
            OpCodes.OP_IF,
                #this branch can only run on CDS-supporting chain
                len(cds_sig), cds_sig,
                len(cds_msg), cds_msg,
                len(cds_pubkey), cds_pubkey,
                OpCodes.OP_CHECKDATASIGVERIFY,
                len(self.pub1ser), self.pub1ser,
            OpCodes.OP_ELSE,
                #this branch can run on any chain
                len(self.pub2ser), self.pub2ser,
            OpCodes.OP_ENDIF,
            OpCodes.OP_CHECKSIG
            ])
        assert 76 < len(self.redeemscript) <= 255  # simplify push in scriptsig; note len is around 200.

        self.address = Address.from_multisig_script(self.redeemscript)

        # make dummy scripts of correct size for size estimation.
        self.dummy_scriptsig_redeem = '01'*(4 + 72 + len(self.redeemscript))
        self.dummy_scriptsig_refund = '00'*(4 + 72 + len(self.redeemscript))

    def makeinput(self, prevout_hash, prevout_n, value, mode):
        """
        Construct an unsigned input for adding to a transaction. scriptSig is
        set to a dummy value, for size estimation.

        (note: Transaction object will fail to broadcast until you sign and run `completetx`)
        """
        if mode == 'redeem':
            scriptSig = self.dummy_scriptsig_redeem
            pubkey = self.pub1ser
        elif mode == 'refund':
            scriptSig = self.dummy_scriptsig_refund
            pubkey = self.pub2ser
        else:
            raise ValueError(mode)

        txin = dict(
            prevout_hash = prevout_hash,
            prevout_n = prevout_n,
            sequence = 0xffffffff,
            scriptSig = scriptSig,

            type = 'unknown',
            address = self.address,
            scriptCode = self.redeemscript.hex(),
            num_sig = 1,
            signatures = [None],
            x_pubkeys = [pubkey.hex()],
            value = value,
            )
        return txin

    def signtx(self, tx):
        """generic tx signer for compressed pubkey"""
        tx.sign(self.keypairs)

    def completetx(self, tx):
        """
        Completes transaction by creating scriptSig. You need to sign the
        transaction before using this (see `signtx`). `secret` may be bytes
        (if redeeming) or None (if refunding).

        This works on multiple utxos if needed.
        """

        for txin in tx.inputs():
            # find matching inputs
            if txin['address'] != self.address:
                continue
            sig = txin['signatures'][0]
            if not sig:
                continue
            sig = bytes.fromhex(sig)

            if txin['scriptSig'] == self.dummy_scriptsig_redeem:
                script = [
                    len(sig), sig,
                    OpCodes.OP_1,
                    0x4c, len(self.redeemscript), self.redeemscript,
                    ]
            elif txin['scriptSig'] == self.dummy_scriptsig_refund:
                script = [
                    len(sig), sig,
                    OpCodes.OP_0,
                    0x4c, len(self.redeemscript), self.redeemscript,
                    ]
            else:
                # already completed..?
                continue
            txin['scriptSig'] = joinbytes(script).hex()
        # need to update the raw, otherwise weird stuff happens.
        tx.raw = tx.serialize()
