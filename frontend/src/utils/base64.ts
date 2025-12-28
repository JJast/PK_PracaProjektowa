
// Utility function to convert base64 to ArrayBuffer
export function base64ToArrayBuffer(input: string): ArrayBuffer {
    console.log('Decoding base64:', input);
    input = input.replace(/-/g, '+').replace(/_/g, '/');
  
    // Add missing padding:
    const pad = input.length % 4;
    if (pad) {
        input += '='.repeat(4 - pad);
    }

    var binaryString = atob(input);

    var bytes = new Uint8Array(binaryString.length);
    for (var i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// Utility function to convert ArrayBuffer to base64url
export function arrayBufferToBase64(buffer: ArrayBuffer) {
    var binary = '';
    var bytes = new Uint8Array(buffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode( bytes[ i ] );
    }
    return window.btoa( binary );
}