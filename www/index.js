import * as wasm from "pqc_kyber";

const generateKeyButton = document.getElementById("generatekey");
const encapButton = document.getElementById("encapsulate");
const decapButton = document.getElementById("decapsulate");
const movebutton = document.getElementById("movebelow");
const movebutton2 = document.getElementById("movebelow2");
const clearButton = document.getElementById("clear");
const checkButton = document.getElementById("check");

const pubKeyBox = document.getElementById("pubkeybox");
const pubKeyBox2 = document.getElementById("pubkeybox2");
const privKeyBox = document.getElementById("privkeybox");
const privKeyBox2 = document.getElementById("privkeybox2");
const cipherTextBox = document.getElementById("ciphertext");
const cipherTextBox2 = document.getElementById("ciphertext2");
const sharedTextBox = document.getElementById("sharedkey");
const sharedTextBox2 = document.getElementById("sharedkey2");

clearButton.addEventListener("click", event => {
    var elements = document.getElementsByTagName("input");
    for (var i=0; i < elements.length; i++) {
        elements[i].value = "";
    }
});

generateKeyButton.addEventListener("click", event => {
    let keys = wasm.keypair();
    const pubKey = keys.pubkey;
    const privKey = keys.secret;

    pubKeyBox.value = toHexString(pubKey);
    privKeyBox.value = toHexString(privKey);
    // TODO: Add a base64 option
    // pubKeyBox.value = Buffer.from(pubKey).toString('base64');    
});
    
encapButton.addEventListener("click", event => {
    try {
        let encapsulated = wasm.encapsulate(hexToBytes(pubKeyBox2.value));
        cipherTextBox.value = toHexString(encapsulated.ciphertext);
        sharedTextBox.value = toHexString(encapsulated.shared_secret);
    }
    catch(err) {
        alert("Error Encapsulating");
    }
});
    
decapButton.addEventListener("click", event => {
    try {
        let decapsulated = wasm.decapsulate(
            hexToBytes(cipherTextBox2.value), 
            hexToBytes(privKeyBox2.value)
        );
        sharedTextBox2.value = toHexString(decapsulated);
    }
    catch(err) {
        alert("Error Decapsulating");
    }
});

movebutton.addEventListener("click", event => {
    pubKeyBox2.value = pubKeyBox.value;
    privKeyBox2.value = privKeyBox.value;
});

movebutton2.addEventListener("click", event => {
    cipherTextBox2.value = cipherTextBox.value;
});

checkButton.addEventListener("click", event => {
   if (cipherTextBox2.value == cipherTextBox.value){ 
       alert("Shared Keys Match") 
    }
    else {
        alert("Failed - Shared Keys Don't Match")
    };
});

function toHexString(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) {
        var current = bytes[i] < 0 ? bytes[i] + 256 : bytes[i];
        hex.push((current >>> 4).toString(16));
        hex.push((current & 0xF).toString(16));
    }
    return hex.join("");
}

function hexToBytes(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2)
    bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}


