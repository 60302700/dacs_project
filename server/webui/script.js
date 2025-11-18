async function register(){
    uname = document.getElementById('username').value

    const dataPayload = {
        username: uname,
        device_id: "deviceId"
    };

    response = await fetch("http://127.0.0.1:5000/register",{
        method:"POST",
        headers: {
            'Content-Type': 'application/json' // This line was added/corrected
        },
        body: JSON.stringify(dataPayload)
        }
    )

    return await response }
