async function sha256Hash(message) {
    // Encode the string into a Uint8Array
    const textEncoder = new TextEncoder();
    const data = textEncoder.encode(message);
  
    // Hash the data
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  
    // Convert the ArrayBuffer to a hexadecimal string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hexHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
    return hexHash;
  }
  
  async function devIDreq() {
    const canvas = document.createElement('canvas');
    let n
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return 'Unknown GPU';
    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    if (debugInfo) {
        return await sha256Hash(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL))
    }
}

function devhash() {
    const msg = document.getElementById("device_idmsg");
    msg.classList.toggle("is-visible");
    msg.style.transition = "ease 0.2s"

    if (msg.style.display === "none" || msg.style.display === "") {
        msg.style.display = "flex";  // show
    } else {
        msg.style.display = "none";  // hide
    }
}

async function deviceID() {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return 'Unknown GPU';
    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    if (debugInfo) document.getElementById("id").innerHTML =  await sha256Hash(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL));
}

window.onload = deviceID;

async function getID(){
    return await deviceID()
}

async function downloadfile(output) {
    let file = output.file
    let fname = file.filename
    delete file.filename
    file = JSON.stringify(file, null, 2)
    let blob = new Blob([file], {type : "application/json"})
    let blobUrl = URL.createObjectURL(blob)
    let downloadLink = document.createElement("a")
    downloadLink.href = blobUrl
    downloadLink.download = fname
    downloadLink.click()
    URL.revokeObjectURL(blobUrl)
}


async function register(){
    event.preventDefault()
    let uname = document.getElementById('username').value
    let msg = document.getElementById('output')

    const dataPayload = {
        username: uname,
        device_id: await getID()
    }

    if (uname.length == 0){
        msg.style = "display:blockcolor:red"
        msg.innerHTML = "Please Enter A Username"
    } else {

    response = await fetch("http://127.0.0.1:5000/register",{
        method:"POST",
        headers: {
            'Content-Type': 'application/json' // This line was added/corrected
        },
        body: JSON.stringify(dataPayload)
        }
    )    
    let output = await response.json()
    let state = output.status
    if (state === "Err"){
        msg.style = "display:blockcolor:red"
        msg.innerHTML = output.msg
    } else {
        msg.style = "display:block"
        msg.innerHTML = output.msg
        downloadfile(output)
    }}

     }


async function priKeyBytes(key){
    key.replace()
}

async function decryptPrivateKeyAES(b64Encrypted, pin) {
    // 1. Base64 decode → ArrayBuffer
    const encryptedBlob = Uint8Array.from(atob(b64Encrypted), c => c.charCodeAt(0))

    // 2. Extract salt, nonce, ciphertext
    const salt = encryptedBlob.slice(0, 16)       // first 16 bytes
    const nonce = encryptedBlob.slice(16, 28)     // next 12 bytes
    const ciphertext = encryptedBlob.slice(28)    // rest (ciphertext + tag)

    // 3. Derive key using PBKDF2-HMAC-SHA256 with 200k iterations
    const encoder = new TextEncoder()
    const pinKey = await crypto.subtle.importKey(
        "raw",
        encoder.encode(pin),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    )

    const aesKey = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 200000,
            hash: "SHA-256",
        },
        pinKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["decrypt"]
    )

    // 4. Decrypt AES-GCM
    try {
        const decrypted = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: nonce,
              // no AAD => no "additionalData" field
            },
            aesKey,
            ciphertext
        )

        // Convert decrypted ArrayBuffer → string
        const decoder = new TextDecoder()
        return decoder.decode(decrypted).replace("-----BEGIN PRIVATE KEY-----","").replace("-----END PRIVATE KEY-----","").replace(/\s+/g, "")
    } catch (err) {
        console.error("Decryption failed:", err)
        return null
    }
}

async function importRSAPrivateKey(clean) {
    const binary = Uint8Array.from(atob(clean), c => c.charCodeAt(0));
    return await crypto.subtle.importKey(
        "pkcs8",
        binary,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        false,
        ["decrypt"] // important
    );
}

function base64ToArrayBuffer(b64) {
    let b64output =  Uint8Array.fromBase64(b64)
    return b64output.buffer
}

async function challenge(){
    let file = document.getElementById("json")
    info = file.files[0]
    info = await JSON.parse(await info.text())
    loginoutput = document.getElementById('loginoutput')
    username = info.user
    priKey = info.Private_Key
    Pin = info.Pin
    
    // Asking For Challenge
    x = await fetch("/challenge",
         {method:"POST",headers:{'Content-Type':'application/json'},
        body:JSON.stringify({"username":username})})
    data = await x.json()
    console.log(data)
    let status = data.status
    if (status == "Err"){
        loginoutput.innerHTML = data.msg
        return
    }
    // gets the challenge and converts it into buffer
    let challenge = data.challenge
    challenge = base64ToArrayBuffer(challenge)
    
    //Private Key In Binary 
    let dePrivateKey = await decryptPrivateKeyAES(priKey,Pin)
    let dePrivateKeybin = await importRSAPrivateKey(dePrivateKey)
    
    //decrypted word
    let decrypted = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        dePrivateKeybin,
        challenge
    );
    
    hiddeninputanswer = document.getElementById('hiddeninputanswer')
    hiddenusername = document.getElementById('hiddeninputuser')
    hiddendevid = document.getElementById('hiddendevid')
    hiddeninputanswer.value = new TextDecoder().decode(decrypted)    
    hiddenusername.value = username
    hiddendevid.value = await devIDreq()
    form = document.getElementById('form')
    form.submit()
}

function copyHash() {
    const text = document.getElementById("id").textContent;
    navigator.clipboard.writeText(text);
}

async function logout(){
    username = document.getElementsByClassName('user-btn')[0].textContent
    x = await fetch("/logout",
        {method:"POST",headers:{'Content-Type':'application/json'},
       body:JSON.stringify({"username":username})})
}