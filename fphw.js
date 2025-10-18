(function(global, $) {
    'use strict';

    if (!global.APP_CONFIG || !global.APP_CONFIG.secretKey) {
        throw new Error('APP_CONFIG.secretKey is missing. Include config.js before this script.');
    }

    var secretKey = global.APP_CONFIG.secretKey;

    var utils = {
        sha256: async function(str) {
            const encoder = new TextEncoder();
            const data = encoder.encode(str);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        },
        prepareKey: function(keyStr) {
            const encoder = new TextEncoder();
            let keyBuffer = encoder.encode(keyStr);
            if (keyBuffer.length > 32) keyBuffer = keyBuffer.slice(0, 32);
            else if (keyBuffer.length < 32) {
                const padded = new Uint8Array(32);
                padded.set(keyBuffer);
                keyBuffer = padded;
            }
            return keyBuffer;
        },
        encryptDeterministic: async function(text, keyStr) {
            const encoder = new TextEncoder();
            const data = encoder.encode(text);
            const iv = new Uint8Array(12);
            const keyBuffer = this.prepareKey(keyStr);
            const cryptoKey = await window.crypto.subtle.importKey('raw', keyBuffer, { name: 'AES-GCM' }, false, ['encrypt']);
            const encrypted = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, cryptoKey, data);
            const combined = new Uint8Array(iv.length + encrypted.byteLength);
            combined.set(iv, 0);
            combined.set(new Uint8Array(encrypted), iv.length);
            return btoa(String.fromCharCode(...combined));
        },
        decryptDeterministic: async function(encryptedB64, keyStr) {
            const decoder = new TextDecoder();
            const combined = new Uint8Array(atob(encryptedB64).split('').map(c => c.charCodeAt(0)));
            const iv = combined.slice(0, 12);
            const data = combined.slice(12);
            const keyBuffer = this.prepareKey(keyStr);
            const cryptoKey = await window.crypto.subtle.importKey('raw', keyBuffer, { name: 'AES-GCM' }, false, ['decrypt']);
            const decrypted = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, cryptoKey, data);
            return decoder.decode(decrypted);
        },
        generateFingerprint: async function(ip, resolution, secretKey) {
            const jsonStr = JSON.stringify({ ip, resolution });
            const encrypted = await this.encryptDeterministic(jsonStr, secretKey);
            const hash = await this.sha256(encrypted);
            return { hash: hash.substring(0, 32), encrypted };
        },
        parseFingerprint: async function(encrypted, secretKey) {
            try {
                const decrypted = await this.decryptDeterministic(encrypted, secretKey);
                return JSON.parse(decrypted);
            } catch (e) {
                return null;
            }
        }
    };

    var Fingerprinter = {
        getIPWebRTC: function(callback) {
            var RTCPeerConnection = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
            if (!RTCPeerConnection) {
                callback(null);
                return;
            }
            var pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
            var ips = [];
            pc.createDataChannel('');
            pc.createOffer().then(function(offer) { return pc.setLocalDescription(offer); }).catch(function(e) {});
            pc.onicecandidate = function(ice) {
                if (!ice || !ice.candidate || !ice.candidate.candidate) return;
                var myIP = /([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/.exec(ice.candidate.candidate);
                if (myIP) ips.push(myIP[1]);
                if (ips.length > 0) {
                    pc.onicecandidate = null;
                    callback(ips[0]);
                }
            };
        },
        getIPAPI: function(callback) {
            $.get('https://httpbin.org/ip', function(data) {
                callback(data.origin);
            }).fail(function() {
                $.get('https://api.ipify.org?format=json', function(data) {
                    callback(data.ip);
                }).fail(function() {
                    callback(null);
                });
            });
        },
        getIP: function(callback) {
            var self = this;
            this.getIPWebRTC(function(ip) {
                if (ip) callback(ip);
                else self.getIPAPI(callback);
            });
        },
        getFingerprint: async function(callback) {
            var self = this;
            this.getIP(function(ip) {
                if (!ip) {
                    callback(null);
                    return;
                }
                var resolution = { width: screen.width, height: screen.height };
                utils.generateFingerprint(ip, resolution, secretKey).then(function(result) {
                    callback(result.hash, result.encrypted);
                });
            });
        },
        parseFingerprint: async function(encrypted, callback) {
            const data = await utils.parseFingerprint(encrypted, secretKey);
            callback(data);
        }
    };

    global.Fingerprinter = Fingerprinter;
})(window, jQuery); 
