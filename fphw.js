(function(global, $) {
    'use strict';

    var utils = {
        sha256: async function(str) {
            const encoder = new TextEncoder();
            const data = encoder.encode(str);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
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
            pc.createOffer()
                .then(function(offer) { return pc.setLocalDescription(offer); })
                .catch(function() {});
            pc.onicecandidate = function(ice) {
                if (!ice || !ice.candidate || !ice.candidate.candidate) return;
                var match = /([0-9]{1,3}(\.[0-9]{1,3}){3})/.exec(ice.candidate.candidate);
                if (match) {
                    ips.push(match[1]);
                    pc.onicecandidate = null;
                    callback(ips[0]);
                }
            };
            setTimeout(function() {
                if (ips.length === 0) {
                    pc.onicecandidate = null;
                    callback(null);
                }
            }, 2000);
        },

        getIPAPI: function(callback) {
            $.get('https://httpbin.org/ip')
                .done(function(data) {
                    callback(data.origin ? data.origin.split(',')[0].trim() : null);
                })
                .fail(function() {
                    $.get('https://api.ipify.org?format=json')
                        .done(function(data) {
                            callback(data.ip || null);
                        })
                        .fail(function() {
                            callback(null);
                        });
                });
        },

        getIP: function(callback) {
            var self = this;
            this.getIPWebRTC(function(ip) {
                if (ip) {
                    callback(ip);
                } else {
                    self.getIPAPI(callback);
                }
            });
        },

        getFingerprint: async function(callback) {
            var self = this;
            this.getIP(function(ip) {
                var resolution = { width: screen.width, height: screen.height };
                var fingerprintData = JSON.stringify({
                    ip: ip || 'unknown',
                    resolution: resolution
                });
                utils.sha256(fingerprintData).then(function(hash) {
                    callback(hash.substring(0, 32));
                });
            });
        }
    };

    global.Fingerprinter = Fingerprinter;
})(window, jQuery);
