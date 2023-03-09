# convert from a BIP39 mnemonic to an Algorand mnemonic.

from bip_utils import (
    AlgorandMnemonicGenerator, Bip32KholawEd25519, Bip39SeedGenerator,
    Ed25519PrivateKey
)

from algosdk import account, mnemonic

def convert_seed(bip39_mnemonic: str, passphrase: str, ledger_account: int):
    bip39_seed_bytes = Bip39SeedGenerator(bip39_mnemonic).Generate(passphrase)
    bip32_ctx = Bip32KholawEd25519.FromSeedAndPath(bip39_seed_bytes, f"m/44'/283'/{ledger_account}'/0/0")
    priv_key_bytes = bip32_ctx.PrivateKey().Raw().ToBytes()[:Ed25519PrivateKey.Length()]
    return AlgorandMnemonicGenerator().FromEntropy(priv_key_bytes).ToStr()

# Ledger recovery data
bip39_mnemonic = ""
passphrase = ""
ledger_account = 1

algorand_mnemonic = convert_seed(bip39_mnemonic,passphrase,ledger_account)
algorand_address = account.address_from_private_key(mnemonic.to_private_key(algorand_mnemonic))

print("\nALGORAND\n")
print(f"  Algorand mnemonic: {algorand_mnemonic}")
print(f"  Algorand address: {algorand_address}\n")