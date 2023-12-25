import hashlib
import binascii
import copy
import datetime
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256


def sha256(message):
    """hashes a message
    :param message: string data
    :return: string representation of hash"""
    return hashlib.sha256(message.encode('utf-8')).hexdigest()


class Node:
    """A class for representing a single node"""

    def __init__(self, name):
        self.name = name
        self._private_key = RSA.generate(1024)
        self._public_key = self._private_key.public_key()

    @property
    def identity(self):
        """hexadecimal representation of public key"""
        return binascii.hexlify(self._public_key.export_key()).decode("ASCII")

    @property
    def signer(self):
        return PKCS1_v1_5.new(self._private_key)


class Transaction:
    """A class for representing a transaction"""

    def __init__(self, sender, receiver, value):
        """
        :param sender: sender object
        :param receiver: receiver object
        :param value: value to be transferred
        """
        self.sender = sender
        self.receiver = receiver
        self.value = value
        self.timestamp = datetime.datetime.now()

    def to_dict(self):
        """return dictionary representation of the transaction"""
        return {
            "sender": self.sender.identity,
            "receiver": self.receiver.identity,
            "value": self.value,
            "time": self.timestamp
        }

    def sign(self):
        """sign the transaction using pycryptodome's SHA256 and the sender's private key"""
        signer = self.sender.signer
        h = SHA256.new(str(self.to_dict()).encode('utf-8'))
        return binascii.hexlify(signer.sign(h)).decode('ASCII')

    def __str__(self):
        str_rep = f"{self.sender.name} sent {self.receiver.name} {self.value} coins"
        str_rep += f" at {self.timestamp.strftime('%m/%d/%Y, %H:%M:%S')}"
        return str_rep


class Transactions:
    """A class for managing transaction queue"""

    def __init__(self):
        self.lst = []
        self.count = 0

    def transfer(self, sender, receiver, value):
        """Create a new transaction and add it to transaction queue"""
        t = Transaction(sender, receiver, value)
        self.lst.append(t)
        self.count += 1

    def dump(self):
        """printing for debugging purposes"""

        print(f"amount of transactions: {self.count}")
        for transaction in self.lst:
            print(transaction)

    def clear(self):
        """clear transaction queue"""

        self.lst.clear()
        self.count = 0

    def __copy__(self):
        """Create a copy of the Transactions object"""

        new_transactions = Transactions()
        new_transactions.lst = self.lst.copy()
        new_transactions.count = self.count
        return new_transactions


class Block:
    """A class for representing a single block"""

    def __init__(self, verified_transactions, previous_hash, difficulty):
        self.verified_transactions = copy.copy(verified_transactions)
        self.previous_hash = previous_hash
        self.difficulty = difficulty
        self.transaction_hash = self.compute_transaction_hash()
        self.nonce = None

    def compute_transaction_hash(self):
        """compute hash of all transactions"""

        str_rep = ""
        for transaction in self.verified_transactions.lst:
            sign = transaction.sign()
            str_rep += sign

        return sha256(str_rep)

    def header_to_dict(self):
        """return dictionary representation of the block header"""

        return {
            "previous_hash": self.previous_hash,
            "difficulty": self.difficulty,
            "transaction_hash": self.transaction_hash,
            "nonce": self.nonce
        }

    def mine(self):
        """Implement proof of work:
        find a suitable nonce and return the block hash"""

        # checking suitability for nonce 0
        self.nonce = 0
        data = str(self.header_to_dict())

        digest, success = self.validate_difficulty(data)
        while not success:
            self.nonce += 1
            data = str(self.header_to_dict())
            digest, success = self.validate_difficulty(data)

        return digest

    def validate_difficulty(self, data):
        """check if hash of block suits difficulty"""

        digest = sha256(data)

        if digest.endswith("0" * self.difficulty):
            return digest, True
        else:
            return digest, False


class Blockchain:
    """A class for representing a blockchain"""

    def __init__(self):
        self.lst = []
        self.count = 0
        self.last_hash = ""

    def create_block(self, verified_transactions, difficulty):
        """create a new block and add it to blockchain"""

        b = Block(verified_transactions, self.last_hash, difficulty)
        self.lst.append(b)
        self.count += 1

    def mine_last_block(self):
        """mine last block and update last block hash"""

        self.last_hash = self.lst[self.count-1].mine()

    def dump(self):
        """printing for debugging purposes"""

        print(f"amount of blocks: {self.count}")
        for i in range(self.count):
            block = self.lst[i]
            print(f"block #{i}:")
            block.verified_transactions.dump()
            print("-----------")


def main():
    blockchain = Blockchain()
    transactions = Transactions()

    arad = Node("arad")
    alon = Node("alon")
    daniel = Node("daniel")
    tyom = Node("tyom")
    roey = Node("roey")
    omer = Node("omer")

    transactions.transfer(arad, alon, 10)
    time.sleep(1)
    transactions.transfer(daniel, tyom, 7)
    time.sleep(1)
    transactions.transfer(tyom, alon, 11)
    time.sleep(1)

    transactions.dump()
    print("\n"*4)
    blockchain.create_block(transactions, 2)
    blockchain.mine_last_block()
    transactions.clear()

    transactions.transfer(roey, omer, 3)
    time.sleep(1)
    transactions.transfer(daniel, omer, 20)
    time.sleep(1)
    transactions.transfer(arad, roey, 6)
    transactions.transfer(alon, tyom, 6)

    blockchain.create_block(transactions, 2)
    blockchain.mine_last_block()
    transactions.clear()
    blockchain.dump()


if __name__ == "__main__":
    main()