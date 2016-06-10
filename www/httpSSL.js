var httpSSL = function() {
};

httpSSL.getHttpSSLRes = function( success, fail, url,parhKey, password) {
    cordova.exec( success, fail, "httpSSL", "cordovaHttpSSL", [url,parhKey,password] );
};

module.exports = httpSSL;
