/*global cordova, module*/
module.exports = {
    initKey: function (successCallback, errorCallback) {
        cordova.exec(successCallback, errorCallback, "Libsodium", "initKey", []);
    },
    cryptobox_create: function (plainText, publicKey, SecretKey, successCallback, errorCallback) {
        cordova.exec(successCallback, errorCallback, "Libsodium", "cryptobox_create", [plainText, publicKey, SecretKey]);
    },
    cryptobox_open: function (cipherText, publicKey, nonce, SecretKey, successCallback, errorCallback) {
        cordova.exec(successCallback, errorCallback, "Libsodium", "cryptobox_open", [cipherText, publicKey, nonce, SecretKey]);
    }
};