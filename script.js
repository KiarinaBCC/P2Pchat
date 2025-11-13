// Secure P2P Chat - Serverless WebRTC with E2EE
// Uses native WebRTC APIs, ECDH for key exchange, AES-256-GCM for messages
// Signaling via manual copy-paste of SDP strings with username/Peer ID matching
// Peer IDs: Local incremental simulation (per-browser sequencing via localStorage; global requires server)
// Security: E2EE, input validation, no persistent storage of messages/keys

(function() {
    'use strict';

    // Warn if not secure context (WebRTC prefers HTTPS)
    if (!window.isSecureContext) {
        console.warn('Warning: Not in a secure context. Use HTTPS or localhost for production.');
    }

    // Global vars
    let ownUsername = null;
    let ownPeerId = null;
    let targetUsername = null;
    let targetPeerId = null;
    let peerUsername = null;
    let peerPeerId = null;
    let pc = null;
    let dc = null;
    let ownKeyPair = null;
    let peerPublicKey = null;
    let aesKey = null;
    let isCaller = false;

    // Base64 utils for binary data
    function uint8ToBase64(uint8Array) {
        let binary = '';
        for (let i = 0; i < uint8Array.length; i++) {
            binary += String.fromCharCode(uint8Array[i]);
        }
        return btoa(binary);
    }

    function base64ToUint8(base64) {
        const binaryString = atob(base64);
        const uint8Array = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            uint8Array[i] = binaryString.charCodeAt(i);
        }
        return uint8Array;
    }

    // Assign unique local Peer ID (incremental simulation)
    function assignPeerId() {
        let maxId = parseInt(localStorage.getItem('maxPeerId') || '0');
        ownPeerId = maxId + 1;
        if (ownPeerId > 100) ownPeerId = 1; // Cycle at max
        localStorage.setItem('maxPeerId', ownPeerId.toString());
        document.getElementById('peerIdSpan').textContent = ownPeerId;
    }

    // Input validation
    function validateUsername(username) {
        return username && /^[a-zA-Z0-9]{1,20}$/.test(username);
    }

    function validateMessage(text) {
        return text && /^[a-zA-Z0-9\s.,!?]{1,500}$/.test(text); // Basic sanitization, no injections
    }

    // Setup data channel handlers (common for both sides)
    function setupDataChannel() {
        dc.binaryType = 'arraybuffer'; // For potential binary, but using string for simplicity
        dc.onopen = async () => {
            console.log('Data channel open');
            document.getElementById('status').innerHTML = '<p>Connection established. Exchanging keys...</p>';
            document.getElementById('offerSection').style.display = 'none';
            document.getElementById('pasteSection').style.display = 'block';
            document.getElementById('chatSection').style.display = 'block';
            document.getElementById('connectionInfo').textContent = `Connected to ${peerUsername} (ID ${peerPeerId})`;

            // Generate ECDH keypair and send public key
            try {
                ownKeyPair = await window.crypto.subtle.generateKey(
                    { name: 'ECDH', namedCurve: 'P-256' },
                    true,
                    ['deriveKey']
                );
                const publicRaw = await window.crypto.subtle.exportKey('raw', ownKeyPair.publicKey);
                const publicB64 = uint8ToBase64(new Uint8Array(publicRaw));
                dc.send(JSON.stringify({ type: 'key', publicKey: publicB64 }));
            } catch (err) {
                console.error('Key generation error:', err);
                document.getElementById('status').innerHTML = '<p>Error setting up encryption.</p>';
            }
        };

        dc.onmessage = async (event) => {
            const data = event.data;
            if (typeof data !== 'string') return;
            try {
                const msg = JSON.parse(data);
                if (msg.type === 'key') {
                    // Derive shared AES key from peer's public
                    const peerPubRaw = base64ToUint8(msg.publicKey);
                    peerPublicKey = await window.crypto.subtle.importKey(
                        'raw',
                        peerPubRaw,
                        { name: 'ECDH', namedCurve: 'P-256' },
                        false,
                        []
                    );
                    aesKey = await window.crypto.subtle.deriveKey(
                        { name: 'ECDH', public: peerPublicKey },
                        ownKeyPair.privateKey,
                        { name: 'AES-GCM', length: 256 },
                        false,
                        ['encrypt', 'decrypt']
                    );
                    console.log('Keys exchanged successfully');
                    document.getElementById('status').innerHTML = '<p>Encryption ready. Start chatting!</p>';
                } else if (msg.type === 'msg' && aesKey) {
                    // Decrypt and display
                    const iv = base64ToUint8(msg.iv);
                    const ciphertext = base64ToUint8(msg.ciphertext);
                    const decrypted = await window.crypto.subtle.decrypt(
                        { name: 'AES-GCM', iv },
                        aesKey,
                        ciphertext
                    );
                    const text = new TextDecoder().decode(decrypted);
                    appendMessage(peerUsername, text);
                }
            } catch (err) {
                console.error('Message handling error:', err);
            }
        };

        dc.onclose = () => {
            console.log('Data channel closed');
            document.getElementById('status').innerHTML = '<p>Connection closed.</p>';
        };

        dc.onerror = (error) => {
            console.error('Data channel error:', error);
            document.getElementById('status').innerHTML = '<p>Connection error. Check console.</p>';
        };
    }

    // Append message to chat log
    function appendMessage(sender, text) {
        const log = document.getElementById('chatLog');
        const p = document.createElement('p');
        p.textContent = `${sender}: ${text}`;
        log.appendChild(p);
        log.scrollTop = log.scrollHeight;
    }

    // Send encrypted message
    async function sendMessage() {
        const input = document.getElementById('msgInput');
        const text = input.value.trim();
        if (!validateMessage(text)) {
            alert('Invalid message (max 500 chars, alphanumeric + basic punctuation)');
            return;
        }
        if (!aesKey) {
            alert('Encryption keys not ready. Wait a moment.');
            return;
        }
        appendMessage(ownUsername, text);
        input.value = '';

        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(text);
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const encrypted = await window.crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                aesKey,
                data
            );
            const ctU8 = new Uint8Array(encrypted);
            const ctB64 = uint8ToBase64(ctU8);
            const ivB64 = uint8ToBase64(iv);
            dc.send(JSON.stringify({ type: 'msg', iv: ivB64, ciphertext: ctB64 }));
        } catch (err) {
            console.error('Encryption error:', err);
            alert('Send failed.');
        }
    }

    // Event listeners
    document.getElementById('setUsername').addEventListener('click', () => {
        const username = document.getElementById('ownUsername').value.trim();
        if (!validateUsername(username)) {
            alert('Invalid username (alphanumeric, 1-20 chars)');
            return;
        }
        ownUsername = username;
        document.getElementById('usernameSection').style.display = 'none';
        document.getElementById('ownInfo').style.display = 'block';
        document.getElementById('connectionSection').style.display = 'block';
        document.getElementById('pasteSection').style.display = 'block'; // Always available for paste
    });

    document.getElementById('initiateConnect').addEventListener('click', async () => {
        const tUsername = document.getElementById('targetUsername').value.trim();
        const tPidStr = document.getElementById('targetPeerId').value.trim();
        if (!validateUsername(tUsername)) {
            alert('Invalid target username');
            return;
        }
        const tPid = parseInt(tPidStr);
        if (isNaN(tPid) || tPid < 1 || tPid > 100) {
            alert('Invalid target Peer ID (1-100)');
            return;
        }
        targetUsername = tUsername;
        targetPeerId = tPid;
        peerUsername = tUsername;
        peerPeerId = tPid;

        document.getElementById('connectionSection').style.display = 'none';
        document.getElementById('offerSection').style.display = 'block';

        // Create peer connection
        pc = new RTCPeerConnection({
            iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
        });
        pc.onicecandidate = (event) => {
            if (event.candidate) {
                // Trickle not used; SDP includes candidates
            }
        };
        pc.ondatachannel = (event) => {
            dc = event.channel;
            setupDataChannel();
        };

        // Create data channel
        dc = pc.createDataChannel('chat');
        setupDataChannel();

        // Create offer
        try {
            const offer = await pc.createOffer();
            await pc.setLocalDescription(offer);
            const sdp = pc.localDescription.sdp;
            const offerStr = `Offer from ${ownUsername} (ID${ownPeerId}) to ${targetUsername} (ID${targetPeerId}): ${sdp}`;
            document.getElementById('offerText').value = offerStr;
            isCaller = true;
        } catch (err) {
            alert(`Error creating offer: ${err.message}`);
            console.error(err);
        }
    });

    document.getElementById('copyOffer').addEventListener('click', () => {
        const textarea = document.getElementById('offerText');
        textarea.select();
        document.execCommand('copy');
        alert('Offer copied to clipboard!');
    });

    document.getElementById('handlePaste').addEventListener('click', async () => {
        const pasted = document.getElementById('pasteText').value.trim();
        if (!pasted) {
            alert('Nothing to paste');
            return;
        }

        const offerRegex = /Offer from ([^ ]+) \(ID(\d+)\) to ([^ ]+) \(ID(\d+)\): (.*)/s;
        const answerRegex = /Answer from ([^ ]+) \(ID(\d+)\) to ([^ ]+) \(ID(\d+)\): (.*)/s;

        const offerMatch = pasted.match(offerRegex);
        if (offerMatch) {
            const [, fromU, fromP, toU, toP, sdp] = offerMatch;
            if (ownUsername !== toU || ownPeerId !== parseInt(toP)) {
                alert('This offer is not addressed to you (username or Peer ID mismatch)!');
                return;
            }
            targetUsername = fromU;
            targetPeerId = parseInt(fromP);
            peerUsername = fromU;
            peerPeerId = parseInt(fromP);

            // Create peer connection as answerer
            pc = new RTCPeerConnection({
                iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
            });
            pc.onicecandidate = () => {};
            pc.ondatachannel = (event) => {
                dc = event.channel;
                setupDataChannel();
            };

            try {
                await pc.setRemoteDescription(new RTCSessionDescription({ type: 'offer', sdp }));
                const answer = await pc.createAnswer();
                await pc.setLocalDescription(answer);
                const answerSdp = pc.localDescription.sdp;
                const answerStr = `Answer from ${ownUsername} (ID${ownPeerId}) to ${targetUsername} (ID${targetPeerId}): ${answerSdp}`;
                document.getElementById('pasteText').value = answerStr;
                document.getElementById('handlePaste').textContent = 'Offer processed - copy answer above';
                document.getElementById('handlePaste').disabled = true;
                document.getElementById('copyAnswer').style.display = 'inline-block';
                isCaller = false;
            } catch (err) {
                alert(`Error processing offer: ${err.message}`);
                console.error(err);
            }
            return;
        }

        const answerMatch = pasted.match(answerRegex);
        if (answerMatch) {
            const [, fromU, fromP, toU, toP, sdp] = answerMatch;
            if (ownUsername !== toU || ownPeerId !== parseInt(toP)) {
                alert('This answer is not addressed to you (username or Peer ID mismatch)!');
                return;
            }
            if (!pc) {
                alert('No active connection. Initiate first.');
                return;
            }
            try {
                await pc.setRemoteDescription(new RTCSessionDescription({ type: 'answer', sdp }));
                document.getElementById('status').innerHTML = '<p>Answer set. Waiting for connection...</p>';
                document.getElementById('handlePaste').textContent = 'Answer processed';
                document.getElementById('handlePaste').disabled = true;
            } catch (err) {
                alert(`Error processing answer: ${err.message}`);
                console.error(err);
            }
            return;
        }

        alert('Invalid connection string format');
    });

    document.getElementById('copyAnswer').addEventListener('click', () => {
        const textarea = document.getElementById('pasteText');
        textarea.select();
        document.execCommand('copy');
        alert('Answer copied to clipboard!');
    });

    document.getElementById('sendMsg').addEventListener('click', sendMessage);
    document.getElementById('msgInput').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

    // Init
    assignPeerId();
})();
