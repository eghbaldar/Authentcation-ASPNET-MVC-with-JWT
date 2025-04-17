function login() {
    const loginData = {
        email: $("#txtEmail").val(),
        password: $("#txtPassword").val()
    };
    fetch('/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(loginData)
    }).then(function () {
        document.location = "/"
    }).catch(err => {
        alert(err);
    })
}