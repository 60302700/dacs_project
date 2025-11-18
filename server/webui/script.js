async function downloadfile(output) {
    let file = output.file
    let fname = file.filename
    delete file.filename
    file = JSON.stringify(file, null, 2)
    let blob = new Blob([file], {type : "application/json"})
    let blobUrl = URL.createObjectURL(blob);
    let downloadLink = document.createElement("a");
    downloadLink.href = blobUrl;
    downloadLink.download = fname;
    downloadLink.click();
    URL.revokeObjectURL(blobUrl);
}


async function register(){
    event.preventDefault();
    let uname = document.getElementById('username').value
    let msg = document.getElementById('output')

    const dataPayload = {
        username: uname,
        device_id: "deviceId"
    };

    if (uname.length == 0){
        msg.style = "display:block;color:red"
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
    console.log(output.file)
    downloadfile(output)

    let state = output.status
    if (state === "Err"){
        msg.style = "display:block;color:red"
        msg.innerHTML = output.msg
    } else {
        msg.style = "display:block"
        msg.innerHTML = output.msg
    }}

     }
