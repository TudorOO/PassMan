//AUXILARY FUNCTIONS

//Encode data into bits
const encode = (data) => {
    const encoder = new TextEncoder()

    return encoder.encode(data)
}

//Generate Iitialization vector for AES-GCM
const generateIV = () => {
    return window.crypto.getRandomValues(new Uint8Array(12))
}

//Generate key for AES-GCM
const generateKey = async (password, salt) => {

    keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        encode(password),
        "PBKDF2",
        false,
        ["deriveBits", "deriveKey"],
    );



    return await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 10000,
            hash: "SHA-512",
        },
        keyMaterial,
        {
            name: "AES-GCM",
            length: 256
        },
        true,
        ["encrypt", "decrypt"],
    );
}

//Get salt and iv from user
const get_salt_iv = async (EMAIL = "", ID = -1, TOKEN) => {
    var salt, iv;
    console.log("Getting salt and iv. email = " + EMAIL + " id = " + ID + " token = " + TOKEN)

    const fd = new FormData();
    fd.append("email", EMAIL);
    fd.append("id", ID);
    fd.append("csrf_token", TOKEN);

    await fetch("/api/get_ivsalt", 
    {
        method: "POST",
        body: fd
    }).then(response => response.json())
    .then(data => {
        salt = unpack(data.salt);
        iv = unpack(data.iv);
    });
    return {"salt": salt, "iv": iv};
}


//Encrypt data
const encrypt = async (data, key, iv = generateIV()) => {

    const encoded = encode(data)
    const cypher = await window.crypto.subtle.encrypt({
        name: "AES-GCM",
        iv: iv,
    }, key, encoded)

    return { cypher, iv }
}

//Pack bytes from encryption into string
const pack = (buffer) => {
    return window.btoa(
        String.fromCharCode.apply(null, new Uint8Array(buffer))
)
}

//Unpack bytes from string
const unpack = (packed) => {
  const string = window.atob(packed)
  const buffer = new ArrayBuffer(string.length)
  const bufferView = new Uint8Array(buffer)
  for (let i = 0; i < string.length; i++) {
    bufferView[i] = string.charCodeAt(i)
  }
  return buffer
}



//FORM FUNCTIONS

async function sendRegisterData(){

    const csrfToken = document.getElementById("csrf_token").value;
    var salt = window.crypto.getRandomValues(new Uint8Array(12))

    var email = document.getElementById("email").value;
    var username = document.getElementById("username").value;
    var password1 = document.getElementById("password1").value;
    var password2 = document.getElementById("password2").value;

    var key = await generateKey(password1, salt);

    const enc1 = await encrypt(password1, key);
    const enc2 = await encrypt(password2, key, enc1.iv);
    const pack1 = pack(enc1.cypher);
    const pack2 = pack(enc2.cypher);

    const sentIV = pack(enc1.iv)
    salt = pack(salt)

    const fd = new FormData();
    fd.append("email", email);
    fd.append("username", username);
    fd.append("password1", pack1);
    fd.append("password2", pack2);
    fd.append("iv", sentIV);
    fd.append("salt", salt);
    fd.append("csrf_token", csrfToken);


    await fetch(
        "/register",
        {
            method: "POST",
            body: fd
        }).then(response => {
            if(response.redirected){
                window.location.href = response.url;
            }else{
                response.text().then(text => {
                    document.body.innerHTML = text;
                });
            }
        })

}

async function sendLoginData(){

    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    const csrfToken = document.getElementById("csrf_token").value;

    if(password != ""){
        //Send encrypted password

        var salt, iv;
        console.log("aaa")
        ivsalt = await get_salt_iv(EMAIL = email, ID = -1,  TOKEN = csrfToken);
        salt = ivsalt.salt;
        iv = ivsalt.iv;

        const key = await generateKey(password, salt);
        var enc1 = await encrypt(password, key, iv=iv)
        const pack1 = pack(enc1.cypher);

        const fd = new FormData();
        fd.append("email", email);
        fd.append("password", pack1);
        fd.append("csrf_token", csrfToken);

        await fetch(
        "/login",
        {
            method: "POST",
            body: fd
        }).then(response => {
            if(response.redirected){
                window.location.href = response.url;
            }else{
                response.text().then(text => {
                    document.body.innerHTML = text;
                });
            }
        })

    }else{
        //Send file

        const fileInput = document.getElementById("backup-file");

        var fd = new FormData();
        fd.append("email", email);
        fd.append("backup-file", fileInput.files[0]);
        fd.append("csrf_token", csrfToken)

        await fetch( 
            '/login', {
                method: "POST",
                body: fd,
            }
        ).then(response => {
            if(response.redirected){
                window.location.href = response.url;
            }else{
                response.text().then(text => {
                    document.body.innerHTML = text;
                });
            }
        })

    }

}

async function sendResetData(){
    const password1 = document.getElementById("password1").value
    const password2 = document.getElementById("password2").value
    const csrf_token = document.getElementById("csrf_token").value

    var salt = window.crypto.getRandomValues(new Uint8Array(12))
    
    var key = await generateKey(password1, salt);

    const enc1 = await encrypt(password1, key);
    const enc2 = await encrypt(password2, key, enc1.iv);
    const pack1 = pack(enc1.cypher);
    const pack2 = pack(enc2.cypher);

    const sentIV = pack(enc1.iv);
    salt = pack(salt);

    var fd = new FormData()
    fd.append("password1", pack1);
    fd.append("password2", pack2);
    fd.append("salt", salt);
    fd.append("iv", sentIV);
    fd.append("csrf_token", csrf_token);

    var url = new URL(window.location.href);

    var partPaths = url.pathname.split('/');
    var access_token = partPaths[partPaths.length - 1];

    fetch("/reset/" + access_token,{
        method: "POST",
        body: fd,
    }).then(response => {
            if(response.redirected){
                window.location.href = response.url;
            }else{
                response.text().then(text => {
                    document.body.innerHTML = text;
                });
            }
        })
}

async function sendKeyDialog(command, id){
    const password = document.getElementById("maspass").value;
    const csrfToken = document.getElementById("csrf_token").value;

    console.log(id)
    console.log(password, csrfToken)

    var salt, iv;
    ivsalt = await get_salt_iv(EMAIL = "", ID = id, TOKEN = csrfToken);
    salt = ivsalt.salt;
    iv = ivsalt.iv;

    console.log("Salt: " + salt);
    console.log("IV: " + iv);

    const key = await generateKey(password, salt);
    var enc1 = await encrypt(password, key, iv=iv)
    const pack1 = pack(enc1.cypher);

    var fd = new FormData();
    fd.append('csrf_token', csrfToken);
    fd.append('submit_button', command);
    fd.append('mpass', pack1);

    if(command[0] == 'N'){
        const app = document.getElementById("app").value;
        fd.append('app', app);
        await fetch('/home', {
            method: 'POST',
            body: fd,
        }).then(response => {
        if(response.redirected){
            window.location.href = response.url;
        }else{
            response.text().then(text => {
                document.body.innerHTML = text;
            });
        }
        })
    }else{
        await fetch('/home', {
            method: 'POST',
            body: fd,
        }).then(response => {
        if(response.redirected){
            window.location.href = response.url;
        }else{
            response.text().then(text => {
                document.body.innerHTML = text;
            });
        }
        })
    }
}