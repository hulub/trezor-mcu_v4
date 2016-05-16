/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "trezor.h"
#include "fsm.h"
#include "messages.h"
#include "bip32.h"
#include "storage.h"
#include "coins.h"
#include "debug.h"
#include "transaction.h"
#include "rng.h"
#include "storage.h"
#include "oled.h"
#include "protect.h"
#include "pinmatrix.h"
#include "layout2.h"
#include "ecdsa.h"
#include "reset.h"
#include "recovery.h"
#include "memory.h"
#include "usb.h"
#include "util.h"
#include "signing.h"
#include "aes.h"
#include "hmac.h"
#include "crypto.h"
#include "base58.h"
#include "bip39.h"
#include "ripemd160.h"
#include "secp256k1.h"
#include "nist256p1.h"

// message methods

static uint8_t msg_resp[MSG_OUT_SIZE];

#define RESP_INIT(TYPE) TYPE *resp = (TYPE *)msg_resp; \
			_Static_assert(sizeof(msg_resp) >= sizeof(TYPE), #TYPE " is too large"); \
			memset(resp, 0, sizeof(TYPE));

void fsm_sendSuccess(const char *text) {
	RESP_INIT(Success);
	if (text) {
		resp->has_message = true;
		strlcpy(resp->message, text, sizeof(resp->message));
	}
	msg_write(MessageType_MessageType_Success, resp);
}

void fsm_sendFailure(FailureType code, const char *text) {
	if (protectAbortedByInitialize) {
		fsm_msgInitialize((Initialize *) 0);
		protectAbortedByInitialize = false;
		return;
	}
	RESP_INIT(Failure);
	resp->has_code = true;
	resp->code = code;
	if (text) {
		resp->has_message = true;
		strlcpy(resp->message, text, sizeof(resp->message));
	}
	msg_write(MessageType_MessageType_Failure, resp);
}

const CoinType *fsm_getCoin(const char *name) {
	const CoinType *coin = coinByName(name);
	if (!coin) {
		fsm_sendFailure(FailureType_Failure_Other, "Invalid coin name");
		layoutHome();
		return 0;
	}
	return coin;
}

const HDNode *fsm_getDerivedNode(uint32_t *address_n, size_t address_n_count) {
	static HDNode node;
	if (!storage_getRootNode(&node)) {
		fsm_sendFailure(FailureType_Failure_NotInitialized,
				"Device not initialized or passphrase request cancelled");
		layoutHome();
		return 0;
	}
	if (!address_n || address_n_count == 0) {
		return &node;
	}
	if (hdnode_private_ckd_cached(&node, address_n, address_n_count) == 0) {
		fsm_sendFailure(FailureType_Failure_Other,
				"Failed to derive private key");
		layoutHome();
		return 0;
	}
	return &node;
}

void fsm_msgInitialize(Initialize *msg) {
	(void) msg;
	recovery_abort();
	signing_abort();
	session_clear(false); // do not clear PIN
	layoutHome();
	fsm_msgGetFeatures(0);
}

void fsm_msgGetFeatures(GetFeatures *msg) {
	(void) msg;
	RESP_INIT(Features);
	resp->has_vendor = true;
	strlcpy(resp->vendor, "bitcointrezor.com", sizeof(resp->vendor));
	resp->has_major_version = true;
	resp->major_version = VERSION_MAJOR;
	resp->has_minor_version = true;
	resp->minor_version = VERSION_MINOR;
	resp->has_patch_version = true;
	resp->patch_version = VERSION_PATCH;
	resp->has_device_id = true;
	strlcpy(resp->device_id, storage_uuid_str, sizeof(resp->device_id));
	resp->has_pin_protection = true;
	resp->pin_protection = storage.has_pin;
	resp->has_passphrase_protection = true;
	resp->passphrase_protection = storage.has_passphrase_protection
			&& storage.passphrase_protection;
#ifdef SCM_REVISION
	int len = sizeof(SCM_REVISION) - 1;
	resp->has_revision = true; memcpy(resp->revision.bytes, SCM_REVISION, len); resp->revision.size = len;
#endif
	resp->has_bootloader_hash = true;
	resp->bootloader_hash.size = memory_bootloader_hash(
			resp->bootloader_hash.bytes);
	if (storage.has_language) {
		resp->has_language = true;
		strlcpy(resp->language, storage.language, sizeof(resp->language));
	}
	if (storage.has_label) {
		resp->has_label = true;
		strlcpy(resp->label, storage.label, sizeof(resp->label));
	}
	resp->coins_count = COINS_COUNT;
	memcpy(resp->coins, coins, COINS_COUNT * sizeof(CoinType));
	resp->has_initialized = true;
	resp->initialized = storage_isInitialized();
	resp->has_imported = true;
	resp->imported = storage.has_imported && storage.imported;
	resp->has_pin_cached = true;
	resp->pin_cached = session_isPinCached();
	resp->has_passphrase_cached = true;
	resp->passphrase_cached = session_isPassphraseCached();
	msg_write(MessageType_MessageType_Features, resp);
}

void fsm_msgPing(Ping *msg) {
	RESP_INIT(Success);

	if (msg->has_button_protection && msg->button_protection) {
		layoutDialogSwipe(DIALOG_ICON_QUESTION, "Cancel", "Confirm", NULL,
				"Do you really want to", "answer to ping?", NULL, NULL, NULL,
				NULL);
		if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall,
		false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Ping cancelled");
			layoutHome();
			return;
		}
	}

	if (msg->has_pin_protection && msg->pin_protection) {
		if (!protectPin(true)) {
			layoutHome();
			return;
		}
	}

	if (msg->has_passphrase_protection && msg->passphrase_protection) {
		if (!protectPassphrase()) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Ping cancelled");
			return;
		}
	}

	if (msg->has_message) {
		resp->has_message = true;
		memcpy(&(resp->message), &(msg->message), sizeof(resp->message));
	}
	msg_write(MessageType_MessageType_Success, resp);
	layoutHome();
}

void fsm_msgChangePin(ChangePin *msg) {
	bool removal = msg->has_remove && msg->remove;
	if (removal) {
		if (storage_hasPin()) {
			layoutDialogSwipe(DIALOG_ICON_QUESTION, "Cancel", "Confirm", NULL,
					"Do you really want to", "remove current PIN?", NULL, NULL,
					NULL, NULL);
		} else {
			fsm_sendSuccess("PIN removed");
			return;
		}
	} else {
		if (storage_hasPin()) {
			layoutDialogSwipe(DIALOG_ICON_QUESTION, "Cancel", "Confirm", NULL,
					"Do you really want to", "change current PIN?", NULL, NULL,
					NULL, NULL);
		} else {
			layoutDialogSwipe(DIALOG_ICON_QUESTION, "Cancel", "Confirm", NULL,
					"Do you really want to", "set new PIN?", NULL, NULL, NULL,
					NULL);
		}
	}
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				removal ? "PIN removal cancelled" : "PIN change cancelled");
		layoutHome();
		return;
	}
	if (!protectPin(false)) {
		layoutHome();
		return;
	}
	if (removal) {
		storage_setPin(0);
		fsm_sendSuccess("PIN removed");
	} else {
		if (protectChangePin()) {
			fsm_sendSuccess("PIN changed");
		} else {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"PIN change failed");
		}
	}
	layoutHome();
}

void fsm_msgWipeDevice(WipeDevice *msg) {
	(void) msg;
	layoutDialogSwipe(DIALOG_ICON_QUESTION, "Cancel", "Confirm", NULL,
			"Do you really want to", "wipe the device?", NULL,
			"All data will be lost.", NULL, NULL);
	if (!protectButton(ButtonRequestType_ButtonRequest_WipeDevice, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, "Wipe cancelled");
		layoutHome();
		return;
	}
	storage_reset();
	storage_reset_uuid();
	storage_commit();
	// the following does not work on Mac anyway :-/ Linux/Windows are fine, so it is not needed
	// usbReconnect(); // force re-enumeration because of the serial number change
	fsm_sendSuccess("Device wiped");
	layoutHome();
}

void fsm_msgFirmwareErase(FirmwareErase *msg) {
	(void) msg;
	fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
			"Not in bootloader mode");
}

void fsm_msgFirmwareUpload(FirmwareUpload *msg) {
	(void) msg;
	fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
			"Not in bootloader mode");
}

void fsm_msgGetEntropy(GetEntropy *msg) {
	layoutDialogSwipe(DIALOG_ICON_QUESTION, "Cancel", "Confirm", NULL,
			"Do you really want to", "send entropy?", NULL, NULL, NULL, NULL);
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"Entropy cancelled");
		layoutHome();
		return;
	}
	RESP_INIT(Entropy);
	uint32_t len = msg->size;
	if (len > 1024) {
		len = 1024;
	}
	resp->entropy.size = len;
	random_buffer(resp->entropy.bytes, len);
	msg_write(MessageType_MessageType_Entropy, resp);
	layoutHome();
}

void fsm_msgGetPublicKey(GetPublicKey *msg) {
	RESP_INIT(PublicKey);

	if (!storage_isInitialized()) {
		fsm_sendFailure(FailureType_Failure_NotInitialized,
				"Device not initialized");
		return;
	}

	if (!protectPin(true)) {
		layoutHome();
		return;
	}

	const HDNode *node = fsm_getDerivedNode(msg->address_n,
			msg->address_n_count);
	if (!node)
		return;

	uint8_t public_key[33];  // copy public key to temporary buffer
	memcpy(public_key, node->public_key, sizeof(public_key));

	if (msg->has_ecdsa_curve_name) {
		const ecdsa_curve *curve = get_curve_by_name(msg->ecdsa_curve_name);
		if (curve) {
			// correct public key (since fsm_getDerivedNode uses secp256k1 curve)
			ecdsa_get_public_key33(curve, node->private_key, public_key);
		}
	}

	if (msg->has_show_display && msg->show_display) {
		layoutPublicKey(public_key);
		if (!protectButton(ButtonRequestType_ButtonRequest_PublicKey, true)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Show public key cancelled");
			layoutHome();
			return;
		}
	}

	resp->node.depth = node->depth;
	resp->node.fingerprint = node->fingerprint;
	resp->node.child_num = node->child_num;
	resp->node.chain_code.size = 32;
	memcpy(resp->node.chain_code.bytes, node->chain_code, 32);
	resp->node.has_private_key = false;
	resp->node.has_public_key = true;
	resp->node.public_key.size = 33;
	memcpy(resp->node.public_key.bytes, public_key, 33);
	resp->has_xpub = true;
	hdnode_serialize_public(node, resp->xpub, sizeof(resp->xpub));
	msg_write(MessageType_MessageType_PublicKey, resp);
	layoutHome();
}

void fsm_msgLoadDevice(LoadDevice *msg) {
	if (storage_isInitialized()) {
		fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
				"Device is already initialized. Use Wipe first.");
		return;
	}

	layoutDialogSwipe(DIALOG_ICON_QUESTION, "Cancel", "I take the risk", NULL,
			"Loading private seed", "is not recommended.",
			"Continue only if you", "know what you are", "doing!", NULL);
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, "Load cancelled");
		layoutHome();
		return;
	}

	if (msg->has_mnemonic && !(msg->has_skip_checksum && msg->skip_checksum)) {
		if (!mnemonic_check(msg->mnemonic)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Mnemonic with wrong checksum provided");
			layoutHome();
			return;
		}
	}

	storage_loadDevice(msg);
	storage_commit();
	fsm_sendSuccess("Device loaded");
	layoutHome();
}

void fsm_msgResetDevice(ResetDevice *msg) {
	if (storage_isInitialized()) {
		fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
				"Device is already initialized. Use Wipe first.");
		return;
	}

	reset_init(msg->has_display_random && msg->display_random,
			msg->has_strength ? msg->strength : 128,
			msg->has_passphrase_protection && msg->passphrase_protection,
			msg->has_pin_protection && msg->pin_protection,
			msg->has_language ? msg->language : 0,
			msg->has_label ? msg->label : 0);
}

void fsm_msgSignTx(SignTx *msg) {
	if (!storage_isInitialized()) {
		fsm_sendFailure(FailureType_Failure_NotInitialized,
				"Device not initialized");
		return;
	}

	if (msg->inputs_count < 1) {
		fsm_sendFailure(FailureType_Failure_Other,
				"Transaction must have at least one input");
		layoutHome();
		return;
	}

	if (msg->outputs_count < 1) {
		fsm_sendFailure(FailureType_Failure_Other,
				"Transaction must have at least one output");
		layoutHome();
		return;
	}

	if (!protectPin(true)) {
		layoutHome();
		return;
	}

	const CoinType *coin = fsm_getCoin(msg->coin_name);
	if (!coin)
		return;
	const HDNode *node = fsm_getDerivedNode(0, 0);
	if (!node)
		return;

	signing_init(msg->inputs_count, msg->outputs_count, coin, node);
}

void fsm_msgCancel(Cancel *msg) {
	(void) msg;
	recovery_abort();
	signing_abort();
}

void fsm_msgTxAck(TxAck *msg) {
	if (msg->has_tx) {
		signing_txack(&(msg->tx));
	} else {
		fsm_sendFailure(FailureType_Failure_SyntaxError,
				"No transaction provided");
	}
}

void fsm_msgCipherKeyValue(CipherKeyValue *msg) {
	if (!storage_isInitialized()) {
		fsm_sendFailure(FailureType_Failure_NotInitialized,
				"Device not initialized");
		return;
	}
	if (!msg->has_key) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "No key provided");
		return;
	}
	if (!msg->has_value) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "No value provided");
		return;
	}
	if (msg->value.size % 16) {
		fsm_sendFailure(FailureType_Failure_SyntaxError,
				"Value length must be a multiple of 16");
		return;
	}
	if (!protectPin(true)) {
		layoutHome();
		return;
	}
	const HDNode *node = fsm_getDerivedNode(msg->address_n,
			msg->address_n_count);
	if (!node)
		return;

	bool encrypt = msg->has_encrypt && msg->encrypt;
	bool ask_on_encrypt = msg->has_ask_on_encrypt && msg->ask_on_encrypt;
	bool ask_on_decrypt = msg->has_ask_on_decrypt && msg->ask_on_decrypt;
	if ((encrypt && ask_on_encrypt) || (!encrypt && ask_on_decrypt)) {
		layoutCipherKeyValue(encrypt, msg->key);
		if (!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"CipherKeyValue cancelled");
			layoutHome();
			return;
		}
	}

	uint8_t data[256 + 4];
	strlcpy((char *) data, msg->key, sizeof(data));
	strlcat((char *) data, ask_on_encrypt ? "E1" : "E0", sizeof(data));
	strlcat((char *) data, ask_on_decrypt ? "D1" : "D0", sizeof(data));

	hmac_sha512(node->private_key, 32, data, strlen((char *) data), data);

	RESP_INIT(CipheredKeyValue);
	if (encrypt) {
		aes_encrypt_ctx ctx;
		aes_encrypt_key256(data, &ctx);
		aes_cbc_encrypt(msg->value.bytes, resp->value.bytes, msg->value.size,
				((msg->iv.size == 16) ? (msg->iv.bytes) : (data + 32)), &ctx);
	} else {
		aes_decrypt_ctx ctx;
		aes_decrypt_key256(data, &ctx);
		aes_cbc_decrypt(msg->value.bytes, resp->value.bytes, msg->value.size,
				((msg->iv.size == 16) ? (msg->iv.bytes) : (data + 32)), &ctx);
	}
	resp->has_value = true;
	resp->value.size = msg->value.size;
	msg_write(MessageType_MessageType_CipheredKeyValue, resp);
	layoutHome();
}

void fsm_msgClearSession(ClearSession *msg) {
	(void) msg;
	session_clear(true); // clear PIN as well
	layoutScreensaver();
	fsm_sendSuccess("Session cleared");
}

void fsm_msgApplySettings(ApplySettings *msg) {
	if (msg->has_label) {
		layoutDialogSwipe(DIALOG_ICON_QUESTION, "Cancel", "Confirm", NULL,
				"Do you really want to", "change label to", msg->label, "?",
				NULL, NULL);
		if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall,
		false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Apply settings cancelled");
			layoutHome();
			return;
		}
	}
	if (msg->has_language) {
		layoutDialogSwipe(DIALOG_ICON_QUESTION, "Cancel", "Confirm", NULL,
				"Do you really want to", "change language to", msg->language,
				"?", NULL, NULL);
		if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall,
		false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Apply settings cancelled");
			layoutHome();
			return;
		}
	}
	if (msg->has_use_passphrase) {
		layoutDialogSwipe(DIALOG_ICON_QUESTION, "Cancel", "Confirm", NULL,
				"Do you really want to",
				msg->use_passphrase ?
						"enable passphrase" : "disable passphrase",
				"encryption?", NULL, NULL, NULL);
		if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall,
		false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Apply settings cancelled");
			layoutHome();
			return;
		}
	}
	if (msg->has_homescreen) {
		layoutDialogSwipe(DIALOG_ICON_QUESTION, "Cancel", "Confirm", NULL,
				"Do you really want to", "change the home", "screen ?", NULL,
				NULL, NULL);
		if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall,
		false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Apply settings cancelled");
			layoutHome();
			return;
		}
	}
	if (!msg->has_label && !msg->has_language && !msg->has_use_passphrase
			&& !msg->has_homescreen) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "No setting provided");
		return;
	}
	if (!protectPin(true)) {
		layoutHome();
		return;
	}
	if (msg->has_label) {
		storage_setLabel(msg->label);
	}
	if (msg->has_language) {
		storage_setLanguage(msg->language);
	}
	if (msg->has_use_passphrase) {
		storage_setPassphraseProtection(msg->use_passphrase);
	}
	if (msg->has_homescreen) {
		storage_setHomescreen(msg->homescreen.bytes, msg->homescreen.size);
	}
	storage_commit();
	fsm_sendSuccess("Settings applied");
	layoutHome();
}

void fsm_msgGetAddress(GetAddress *msg) {
	RESP_INIT(Address);

	if (!storage_isInitialized()) {
		fsm_sendFailure(FailureType_Failure_NotInitialized,
				"Device not initialized");
		return;
	}

	if (!protectPin(true)) {
		layoutHome();
		return;
	}

	const CoinType *coin = fsm_getCoin(msg->coin_name);
	if (!coin)
		return;
	const HDNode *node = fsm_getDerivedNode(msg->address_n,
			msg->address_n_count);
	if (!node)
		return;

	if (msg->has_multisig) {
		layoutProgressSwipe("Preparing", 0);
		if (cryptoMultisigPubkeyIndex(&(msg->multisig), node->public_key) < 0) {
			fsm_sendFailure(FailureType_Failure_Other,
					"Pubkey not found in multisig script");
			layoutHome();
			return;
		}
		uint8_t buf[32];
		if (compile_script_multisig_hash(&(msg->multisig), buf) == 0) {
			fsm_sendFailure(FailureType_Failure_Other,
					"Invalid multisig script");
			layoutHome();
			return;
		}
		ripemd160(buf, 32, buf + 1);
		buf[0] = coin->address_type_p2sh; // multisig cointype
		base58_encode_check(buf, 21, resp->address, sizeof(resp->address));
	} else {
		ecdsa_get_address(node->public_key, coin->address_type, resp->address,
				sizeof(resp->address));
	}

	if (msg->has_show_display && msg->show_display) {
		char desc[16];
		if (msg->has_multisig) {
			strlcpy(desc, "Msig __ of __:", sizeof(desc));
			const uint32_t m = msg->multisig.m;
			const uint32_t n = msg->multisig.pubkeys_count;
			desc[5] = (m < 10) ? ' ' : ('0' + (m / 10));
			desc[6] = '0' + (m % 10);
			desc[11] = (n < 10) ? ' ' : ('0' + (n / 10));
			desc[12] = '0' + (n % 10);
		} else {
			strlcpy(desc, "Address:", sizeof(desc));
		}
		layoutAddress(resp->address, desc);
		if (!protectButton(ButtonRequestType_ButtonRequest_Address, true)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Show address cancelled");
			layoutHome();
			return;
		}
	}

	msg_write(MessageType_MessageType_Address, resp);
	layoutHome();
}

void fsm_msgEntropyAck(EntropyAck *msg) {
	if (msg->has_entropy) {
		reset_entropy(msg->entropy.bytes, msg->entropy.size);
	} else {
		reset_entropy(0, 0);
	}
}

void fsm_msgSignMessage(SignMessage *msg) {
	RESP_INIT(MessageSignature);

	if (!storage_isInitialized()) {
		fsm_sendFailure(FailureType_Failure_NotInitialized,
				"Device not initialized");
		return;
	}

	layoutSignMessage(msg->message.bytes, msg->message.size);
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"Sign message cancelled");
		layoutHome();
		return;
	}

	if (!protectPin(true)) {
		layoutHome();
		return;
	}

	const CoinType *coin = fsm_getCoin(msg->coin_name);
	if (!coin)
		return;
	const HDNode *node = fsm_getDerivedNode(msg->address_n,
			msg->address_n_count);
	if (!node)
		return;

	layoutProgressSwipe("Signing", 0);
	if (cryptoMessageSign(msg->message.bytes, msg->message.size,
			node->private_key, resp->signature.bytes) == 0) {
		resp->has_address = true;
		uint8_t addr_raw[21];
		ecdsa_get_address_raw(node->public_key, coin->address_type, addr_raw);
		base58_encode_check(addr_raw, 21, resp->address, sizeof(resp->address));
		resp->has_signature = true;
		resp->signature.size = 65;
		msg_write(MessageType_MessageType_MessageSignature, resp);
	} else {
		fsm_sendFailure(FailureType_Failure_Other, "Error signing message");
	}
	layoutHome();
}

/* Ring Sign Message implementation
 * ... for now it just sends back a MessageSignature that does not have an address
 * ... the returned message has just the encrypted message
 *  */
void printPoint(curve_point *point, const char *name, uint32_t length) {

	uint8_t bytes[32];
	bn_write_be(&point->x, bytes);

	char text[length + 2];
	memcpy(text, name, length);
	text[length] = '.';
	text[length + 1] = 'x';

	layoutBigNum(bytes, text);
	if (!protectButton(ButtonRequestType_ButtonRequest_PublicKey, true)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"Show public key cancelled");
		layoutHome();
		return;
	}

	bn_write_be(&point->y, bytes);
	text[length + 1] = 'y';
	layoutBigNum(bytes, text);
	if (!protectButton(ButtonRequestType_ButtonRequest_PublicKey, true)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"Show public key cancelled");
		layoutHome();
		return;
	}
}

void printBigNum(bignum256 *num, char *name) {

	uint8_t bytes[32];
	bn_write_be(num, bytes);
	layoutBigNum(bytes, name);
	if (!protectButton(ButtonRequestType_ButtonRequest_PublicKey, true)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"Show public key cancelled");
		layoutHome();
		return;
	}
}

void fsm_msgRingSignMessage(RingSignMessage *msg) {
	if (!storage_isInitialized()) {
		fsm_sendFailure(FailureType_Failure_NotInitialized,
				"Device not initialized");
		return;
	}

	const HDNode *node = fsm_getDerivedNode(NULL, 0);
	if (!node) {
		fsm_sendFailure(FailureType_Failure_Other,
				"fsm_getDerivedNode couldn't get the HDNode without the address info");
		return;
	}

	RESP_INIT(MessageRingSignature);

	// this is for debugging

	// print n
	layoutNumber(msg->n, "n:              ");
	if (!protectButton(ButtonRequestType_ButtonRequest_PublicKey, true)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"Show public key cancelled");
		layoutHome();
		return;
	}

	// print pi
	layoutNumber(msg->pi, "pi:             ");
	if (!protectButton(ButtonRequestType_ButtonRequest_PublicKey, true)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"Show public key cancelled");
		layoutHome();
		return;
	}

	// print message
	layoutEncryptMessage(msg->message.bytes, msg->message.size, false);
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"Ring sign message cancelled");
		layoutHome();
		return;
	}

	layoutProgressSwipe("Ring Signing...", 0);

	curve_point G;
	point_copy(&secp256k1.G, &G);
	printPoint(&G, "G", 1);

	uint8_t parambytes[32];
	bn_write_be(&secp256k1.order, parambytes);
	bignum256 order;
	bn_read_be(parambytes, &order);
	printBigNum(&order, "order");

	bn_write_be(&secp256k1.order_half, parambytes);
	bignum256 order_half;
	bn_read_be(parambytes, &order_half);
	printBigNum(&order_half, "half order");

	bn_write_be(&secp256k1.prime, parambytes);
	bignum256 prime;
	bn_read_be(parambytes, &prime);
	printBigNum(&prime, "prime");

	// implementation of the LSAG generation algorithm
	bignum256 c[msg->n];
	bignum256 s[msg->n];
	curve_point H, Yt, Yi, MathG, MathG1, MathG2, MathH, MathH1, MathH2, MathT,
			Result;
	uint32_t index;

	// turn message into a bignum
	bignum256 m;
	uint8_t mhash[32];
	// hash the message to turn it into 32 byte array
	sha256_Raw(msg->message.bytes, msg->message.size, mhash);
	bn_read_be(mhash, &m);

	// compute h = new bignum out of concatenation of all public keys
	bignum256 h;
	uint8_t hash[32];
	// concatenate all public keys
	uint8_t ytotal[65 * msg->n];
	uint8_t i;
	for (i = 0; i < msg->n; i++)
		memcpy(ytotal + (i * 65), msg->L[i].bytes, 65);
	// h = hash(L)
	sha256_Raw(ytotal, 65 * msg->n, hash); // I do the hashing only once now ... this should be enough
	bn_read_be(hash, &h);

	printBigNum(&h, "h");

	// compute H
	scalar_multiply(&secp256k1, &h, &H);

	printPoint(&H, "H", 1);

	// turn private key into a bignum
	bignum256 privateKeyBigNum;
	bn_read_be(node->private_key, &privateKeyBigNum);

	printBigNum(&privateKeyBigNum, "priv key big num");

	// compute Yt
	point_multiply(&secp256k1, &privateKeyBigNum, &H, &Yt);

	printPoint(&Yt, "Yt", 2);

	// randomly pick u 0 < u < order_half
	bignum256 u;
	generate_k_random(&secp256k1, &u);
	bn_mod(&u, &secp256k1.order_half);

	printBigNum(&u, "u");

	// compute MathG = G * u
	scalar_multiply(&secp256k1, &u, &MathG);

	printPoint(&MathG, "MathG", 5);

	// compute MathH = H * u
	point_multiply(&secp256k1, &u, &H, &MathH);

	printPoint(&MathH, "MathH", 5);

	// compute MathT = MathG + MathH
	// copy MathG into MathT
	point_copy(&MathG, &MathT);
	// add MathH to MathT
	point_add(&secp256k1, &MathH, &MathT);

	printPoint(&MathT, "MathT", 5);

	printBigNum(&m, "m");

	// compute Result = MathT * m
	point_multiply(&secp256k1, &m, &MathT, &Result);

	printPoint(&Result, "Result", 6);

	// c[pi+1] = Result.y
	index = (msg->pi + 1) % msg->n;
	c[index] = Result.y;

	// for loop
	for (i = msg->pi + 1; i < msg->n; i++) {
		// randomly pick s[i]
		generate_k_random(&secp256k1, &s[i]);
		bn_mod(&s[i], &secp256k1.order_half);
		printBigNum(&s[i], "s_i");

		// compute MathG = G*si + Yi*ci
		// compute MathG1 = G*si
		scalar_multiply(&secp256k1, &s[i], &MathG1);
		// compute MAthG2 = Yi*ci
		// generate Yi out of yi
		ecdsa_read_pubkey(&secp256k1, msg->L[i].bytes, &Yi);
		point_multiply(&secp256k1, &c[i], &Yi, &MathG2);
		// copy MathG1 into MathG
		point_copy(&MathG1, &MathG);
		// add MathG2 to MathG
		point_add(&secp256k1, &MathG2, &MathG);

		printPoint(&MathG, "MathG", 5);

		// compute MathH = H*si + Yt*ci
		// compute MathH1 = H*si
		scalar_multiply(&secp256k1, &s[i], &MathH1);
		// compute MAthH2 = Yt*ci
		point_multiply(&secp256k1, &c[i], &Yt, &MathH2);
		// copy MathH1 into MathH
		point_copy(&MathH1, &MathH);
		// add MathH2 to MathH
		point_add(&secp256k1, &MathH2, &MathH);

		printPoint(&MathH, "MathH", 5);

		// compute MathT = MathG + MathH
		// copy MathG into MathT
		point_copy(&MathG, &MathT);
		// add MathH to MathT
		point_add(&secp256k1, &MathH, &MathT);

		// compute Result = MathT * m
		point_multiply(&secp256k1, &m, &MathT, &Result);

		printPoint(&Result, "Result", 6);

		// c[i+1] = Result.y
		index = (i + 1) % msg->n;
		c[index] = Result.y;
	}

	// for loop - from 0 to pi
	for (i = 0; i < msg->pi; i++) {
		// randomly pick s[i]
		generate_k_random(&secp256k1, &s[i]);
		printBigNum(&s[i], "s_i");

		// compute MathG = G*si + Yi*ci
		// compute MathG1 = G*si
		scalar_multiply(&secp256k1, &s[i], &MathG1);
		// compute MAthG2 = Yi*ci
		// generate Yi out of yi
		ecdsa_read_pubkey(&secp256k1, msg->L[i].bytes, &Yi);
		point_multiply(&secp256k1, &c[i], &Yi, &MathG2);
		// copy MathG1 into MathG
		point_copy(&MathG1, &MathG);
		// add MathG2 to MathG
		point_add(&secp256k1, &MathG2, &MathG);

		printPoint(&MathG, "MathG", 5);

		// compute MathH = H*si + Yt*ci
		// compute MathH1 = H*si
		scalar_multiply(&secp256k1, &s[i], &MathH1);
		// compute MAthH2 = Yt*ci
		point_multiply(&secp256k1, &c[i], &Yt, &MathH2);
		// copy MathH1 into MathH
		point_copy(&MathH1, &MathH);
		// add MathH2 to MathH
		point_add(&secp256k1, &MathH2, &MathH);

		printPoint(&MathH, "MathH", 5);

		// compute MathT = MathG + MathH
		// copy MathG into MathT
		point_copy(&MathG, &MathT);
		// add MathH to MathT
		point_add(&secp256k1, &MathH, &MathT);

		// compute Result = MathT * m
		point_multiply(&secp256k1, &m, &MathT, &Result);

		printPoint(&Result, "Result", 6);

		// c[i+1] = Result.y
		index = (i + 1) % msg->n;
		c[index] = Result.y;
	}

	// compute s[pi] = u - x_pi * c_pi ... everything modulo order
	bignum256 temp = c[msg->pi];
	printBigNum(&temp, "c_pi");

	bn_multiply(&privateKeyBigNum, &temp, &secp256k1.order_half);
	printBigNum(&temp, "x_pi * c_pi");

	bn_subtractmod(&u, &temp, &s[msg->pi], &secp256k1.order_half);

	printBigNum(&s[msg->pi], "s_pi");

	resp->c.size = 32;
	bn_write_be(&c[0], resp->c.bytes);

	// set resp->n
	resp->n = msg->n;

	// set resp -> s[]
	resp->s_count = msg->n;
	for (i = 0; i < msg->n; i++) {
		resp->s[i].size = 32;
		bn_write_be(&s[i], resp->s[i].bytes);
	}

	// set rest->Yt
	// copy x coordinate of Yt
	resp->YtDotX.size = 32;
	bn_write_be(&Yt.x, resp->YtDotX.bytes);
	// copy y coordinate of Yt
	resp->YtDotY.size = 32;
	bn_write_be(&Yt.y, resp->YtDotY.bytes);

	msg_write(MessageType_MessageType_MessageRingSignature, resp);
	layoutHome();
}

/* Get Public Key 65 */
void fsm_msgGetPublicKey65(GetPublicKey65 *msg) {
	(void) msg;
	if (!storage_isInitialized()) {
		fsm_sendFailure(FailureType_Failure_NotInitialized,
				"Device not initialized");
		return;
	}

	const HDNode *node = fsm_getDerivedNode(NULL, 0);
	if (!node) {
		fsm_sendFailure(FailureType_Failure_Other,
				"fsm_getDerivedNode couldn't get the HDNode without the address info");
		return;
	}

	RESP_INIT(PublicKey65);

	bignum256 privkey;
	bn_read_be(node->private_key, &privkey);
	printBigNum(&privkey, "priv key");

	curve_point publickey_calculated;
	scalar_multiply(&secp256k1, &privkey, &publickey_calculated);
	printPoint(&publickey_calculated, "Pub calculated", 14);

	uint8_t bytes[65];
	curve_point publickey_generated;
	ecdsa_get_public_key65(&secp256k1, node->private_key, bytes);
	ecdsa_read_pubkey(&secp256k1, bytes, &publickey_generated);
	printPoint(&publickey_generated, "Pub generated", 13);

	resp->publicKey.size = 65;
	ecdsa_get_public_key65(&secp256k1, node->private_key,
			resp->publicKey.bytes);

	// populate resp with the bytes of the public key

	msg_write(MessageType_MessageType_PublicKey65, resp);
	layoutHome();
}

void fsm_msgVerifyMessage(VerifyMessage *msg) {
	if (!msg->has_address) {
		fsm_sendFailure(FailureType_Failure_Other, "No address provided");
		return;
	}
	if (!msg->has_message) {
		fsm_sendFailure(FailureType_Failure_Other, "No message provided");
		return;
	}
	layoutProgressSwipe("Verifying", 0);
	uint8_t addr_raw[21];
	if (!ecdsa_address_decode(msg->address, addr_raw)) {
		fsm_sendFailure(FailureType_Failure_InvalidSignature,
				"Invalid address");
	}
	if (msg->signature.size == 65
			&& cryptoMessageVerify(msg->message.bytes, msg->message.size,
					addr_raw, msg->signature.bytes) == 0) {
		layoutVerifyMessage(msg->message.bytes, msg->message.size);
		protectButton(ButtonRequestType_ButtonRequest_Other, true);
		fsm_sendSuccess("Message verified");
	} else {
		fsm_sendFailure(FailureType_Failure_InvalidSignature,
				"Invalid signature");
	}
	layoutHome();
}

void fsm_msgSignIdentity(SignIdentity *msg) {
	RESP_INIT(SignedIdentity);

	if (!storage_isInitialized()) {
		fsm_sendFailure(FailureType_Failure_NotInitialized,
				"Device not initialized");
		return;
	}

	layoutSignIdentity(&(msg->identity),
			msg->has_challenge_visual ? msg->challenge_visual : 0);
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"Sign identity cancelled");
		layoutHome();
		return;
	}

	if (!protectPin(true)) {
		layoutHome();
		return;
	}

	uint8_t hash[32];
	if (!msg->has_identity
			|| cryptoIdentityFingerprint(&(msg->identity), hash) == 0) {
		fsm_sendFailure(FailureType_Failure_Other, "Invalid identity");
		layoutHome();
		return;
	}

	uint32_t address_n[5];
	address_n[0] = 0x80000000 | 13;
	address_n[1] = 0x80000000 | hash[0] | (hash[1] << 8) | (hash[2] << 16)
			| (hash[3] << 24);
	address_n[2] = 0x80000000 | hash[4] | (hash[5] << 8) | (hash[6] << 16)
			| (hash[7] << 24);
	address_n[3] = 0x80000000 | hash[8] | (hash[9] << 8) | (hash[10] << 16)
			| (hash[11] << 24);
	address_n[4] = 0x80000000 | hash[12] | (hash[13] << 8) | (hash[14] << 16)
			| (hash[15] << 24);

	const HDNode *node = fsm_getDerivedNode(address_n, 5);
	if (!node)
		return;

	uint8_t public_key[33];  // copy public key to temporary buffer
	memcpy(public_key, node->public_key, sizeof(public_key));

	if (msg->has_ecdsa_curve_name) {
		const ecdsa_curve *curve = get_curve_by_name(msg->ecdsa_curve_name);
		if (curve) {
			// correct public key (since fsm_getDerivedNode uses secp256k1 curve)
			ecdsa_get_public_key33(curve, node->private_key, public_key);
		}
	}

	bool sign_ssh = msg->identity.has_proto
			&& (strcmp(msg->identity.proto, "ssh") == 0);

	int result = 0;
	layoutProgressSwipe("Signing", 0);
	if (sign_ssh) { // SSH does not sign visual challenge
		result = sshMessageSign(msg->challenge_hidden.bytes,
				msg->challenge_hidden.size, node->private_key,
				resp->signature.bytes);
	} else {
		uint8_t digest[64];
		sha256_Raw(msg->challenge_hidden.bytes, msg->challenge_hidden.size,
				digest);
		sha256_Raw((const uint8_t *) msg->challenge_visual,
				strlen(msg->challenge_visual), digest + 32);
		result = cryptoMessageSign(digest, 64, node->private_key,
				resp->signature.bytes);
	}

	if (result == 0) {
		if (sign_ssh) {
			resp->has_address = false;
		} else {
			resp->has_address = true;
			uint8_t addr_raw[21];
			ecdsa_get_address_raw(node->public_key, 0x00, addr_raw); // hardcoded Bitcoin address type
			base58_encode_check(addr_raw, 21, resp->address,
					sizeof(resp->address));
		}
		resp->has_public_key = true;
		resp->public_key.size = 33;
		memcpy(resp->public_key.bytes, public_key, 33);
		resp->has_signature = true;
		resp->signature.size = 65;
		msg_write(MessageType_MessageType_SignedIdentity, resp);
	} else {
		fsm_sendFailure(FailureType_Failure_Other, "Error signing identity");
	}
	layoutHome();
}

void fsm_msgEncryptMessage(EncryptMessage *msg) {
	if (!storage_isInitialized()) {
		fsm_sendFailure(FailureType_Failure_NotInitialized,
				"Device not initialized");
		return;
	}
	if (!msg->has_pubkey) {
		fsm_sendFailure(FailureType_Failure_SyntaxError,
				"No public key provided");
		return;
	}
	if (!msg->has_message) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "No message provided");
		return;
	}

	/* Turn the public key into a curve point
	 *
	 */
	curve_point pubkey;
	if (msg->pubkey.size != 33
			|| ecdsa_read_pubkey(&secp256k1, msg->pubkey.bytes, &pubkey) == 0) {
		fsm_sendFailure(FailureType_Failure_SyntaxError,
				"Invalid public key provided");
		return;
	}
	bool display_only = msg->has_display_only && msg->display_only;
	bool signing = msg->address_n_count > 0;
	RESP_INIT(EncryptedMessage);
	const CoinType *coin = 0;
	const HDNode *node = 0;
	uint8_t address_raw[21];
	if (signing) {
		coin = coinByName(msg->coin_name);
		if (!coin) {
			fsm_sendFailure(FailureType_Failure_Other, "Invalid coin name");
			return;
		}
		if (!protectPin(true)) {
			layoutHome();
			return;
		}
		node = fsm_getDerivedNode(msg->address_n, msg->address_n_count);
		if (!node)
			return;
		uint8_t public_key[33];
		ecdsa_get_public_key33(&secp256k1, node->private_key, public_key);
		ecdsa_get_address_raw(public_key, coin->address_type, address_raw);
	}
	layoutEncryptMessage(msg->message.bytes, msg->message.size, signing);
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"Encrypt message cancelled");
		layoutHome();
		return;
	}
	layoutProgressSwipe("Encrypting", 0);
	if (cryptoMessageEncrypt(&pubkey, msg->message.bytes, msg->message.size,
			display_only, resp->nonce.bytes, &(resp->nonce.size),
			resp->message.bytes, &(resp->message.size), resp->hmac.bytes,
			&(resp->hmac.size), signing ? node->private_key : 0,
			signing ? address_raw : 0) != 0) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"Error encrypting message");
		layoutHome();
		return;
	}
	resp->has_nonce = true;
	resp->has_message = true;
	resp->has_hmac = true;
	msg_write(MessageType_MessageType_EncryptedMessage, resp);
	layoutHome();
}

void fsm_msgDecryptMessage(DecryptMessage *msg) {
	if (!storage_isInitialized()) {
		fsm_sendFailure(FailureType_Failure_NotInitialized,
				"Device not initialized");
		return;
	}
	if (!msg->has_nonce) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "No nonce provided");
		return;
	}
	if (!msg->has_message) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "No message provided");
		return;
	}
	if (!msg->has_hmac) {
		fsm_sendFailure(FailureType_Failure_SyntaxError,
				"No message hmac provided");
		return;
	}
	curve_point nonce_pubkey;
	if (msg->nonce.size != 33
			|| ecdsa_read_pubkey(&secp256k1, msg->nonce.bytes, &nonce_pubkey)
					== 0) {
		fsm_sendFailure(FailureType_Failure_SyntaxError,
				"Invalid nonce provided");
		return;
	}
	if (!protectPin(true)) {
		layoutHome();
		return;
	}
	const HDNode *node = fsm_getDerivedNode(msg->address_n,
			msg->address_n_count);
	if (!node)
		return;

	layoutProgressSwipe("Decrypting", 0);
	RESP_INIT(DecryptedMessage);
	bool display_only = false;
	bool signing = false;
	uint8_t address_raw[21];
	if (cryptoMessageDecrypt(&nonce_pubkey, msg->message.bytes,
			msg->message.size, msg->hmac.bytes, msg->hmac.size,
			node->private_key, resp->message.bytes, &(resp->message.size),
			&display_only, &signing, address_raw) != 0) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"Error decrypting message");
		layoutHome();
		return;
	}
	if (signing) {
		base58_encode_check(address_raw, 21, resp->address,
				sizeof(resp->address));
	}
	layoutDecryptMessage(resp->message.bytes, resp->message.size,
			signing ? resp->address : 0);
	protectButton(ButtonRequestType_ButtonRequest_Other, true);
	if (display_only) {
		resp->has_address = false;
		resp->has_message = false;
		memset(resp->address, 0, sizeof(resp->address));
		memset(&(resp->message), 0, sizeof(resp->message));
	} else {
		resp->has_address = signing;
		resp->has_message = true;
	}
	msg_write(MessageType_MessageType_DecryptedMessage, resp);
	layoutHome();
}

void fsm_msgEstimateTxSize(EstimateTxSize *msg) {
	RESP_INIT(TxSize);
	resp->has_tx_size = true;
	resp->tx_size = transactionEstimateSize(msg->inputs_count,
			msg->outputs_count);
	msg_write(MessageType_MessageType_TxSize, resp);
}

void fsm_msgRecoveryDevice(RecoveryDevice *msg) {
	if (storage_isInitialized()) {
		fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
				"Device is already initialized. Use Wipe first.");
		return;
	}
	recovery_init(msg->has_word_count ? msg->word_count : 12,
			msg->has_passphrase_protection && msg->passphrase_protection,
			msg->has_pin_protection && msg->pin_protection,
			msg->has_language ? msg->language : 0,
			msg->has_label ? msg->label : 0,
			msg->has_enforce_wordlist ? msg->enforce_wordlist : false
			);
}

void fsm_msgWordAck(WordAck *msg) {
	recovery_word(msg->word);
}

#if DEBUG_LINK

void fsm_msgDebugLinkGetState(DebugLinkGetState *msg)
{
	(void)msg;
	RESP_INIT(DebugLinkState);

	resp->has_layout = true;
	resp->layout.size = OLED_BUFSIZE;
	memcpy(resp->layout.bytes, oledGetBuffer(), OLED_BUFSIZE);

	if (storage.has_pin) {
		resp->has_pin = true;
		strlcpy(resp->pin, storage.pin, sizeof(resp->pin));
	}

	resp->has_matrix = true;
	strlcpy(resp->matrix, pinmatrix_get(), sizeof(resp->matrix));

	resp->has_reset_entropy = true;
	resp->reset_entropy.size = reset_get_int_entropy(resp->reset_entropy.bytes);

	resp->has_reset_word = true;
	strlcpy(resp->reset_word, reset_get_word(), sizeof(resp->reset_word));

	resp->has_recovery_fake_word = true;
	strlcpy(resp->recovery_fake_word, recovery_get_fake_word(), sizeof(resp->recovery_fake_word));

	resp->has_recovery_word_pos = true;
	resp->recovery_word_pos = recovery_get_word_pos();

	if (storage.has_mnemonic) {
		resp->has_mnemonic = true;
		strlcpy(resp->mnemonic, storage.mnemonic, sizeof(resp->mnemonic));
	}

	if (storage.has_node) {
		resp->has_node = true;
		memcpy(&(resp->node), &(storage.node), sizeof(HDNode));
	}

	resp->has_passphrase_protection = true;
	resp->passphrase_protection = storage.has_passphrase_protection && storage.passphrase_protection;

	msg_debug_write(MessageType_MessageType_DebugLinkState, resp);
}

void fsm_msgDebugLinkStop(DebugLinkStop *msg)
{
	(void)msg;
}

#endif
