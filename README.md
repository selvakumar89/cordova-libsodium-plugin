Plugin Installation

cordova plugin add https://github.com/selvakumar89/cordova-libsodium-plugin.git


libsodium.initKey(function(result){
    // result.pk, result.sk
}, function(err){
    // cordova error
});

libsodium.cryptobox_create(plainText, publicKey, SecretKey, function(result){
    // result.ct, result.nonce
}, function(err){
    // cordova error
});

libsodium.cryptobox_open(cipherText, publicKey, nonce, SecretKey, function(result){
    // result.plainText
}, function(err){
    // cordova error
});

